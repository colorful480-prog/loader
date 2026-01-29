from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.responses import FileResponse
import redis
import uuid, time, os, json

app = FastAPI()

# ================= REDIS CONFIG =================

REDIS_URL = os.getenv("REDIS_URL")
if not REDIS_URL:
    raise RuntimeError("REDIS_URL not set")

r = redis.Redis.from_url(
    REDIS_URL,
    decode_responses=True
)


SESSION_TTL = 120

# ================= UTILS =================
def key_expire_time(key: str) -> int:
    now = int(time.time())
    if not key[-1].isdigit():
        return 0
    t = key[-1]
    if t == "1":
        return now + 86400
    if t == "2":
        return now + 604800
    if t == "3":
        return now + 2592000
    return 0

def create_session(hwid: str) -> str:
    sid = str(uuid.uuid4())
    r.setex(
        f"session:{sid}",
        SESSION_TTL,
        json.dumps({"hwid": hwid})
    )
    return sid

def validate_session(sid: str, hwid: str) -> bool:
    data = r.get(f"session:{sid}")
    if not data:
        return False

    s = json.loads(data)
    if s["hwid"] != hwid:
        return False

    return True

# ================= MODELS =================
class AuthReq(BaseModel):
    key: str
    hwid: str

class FileReq(BaseModel):
    session_id: str
    hwid: str

# ================= ROUTES =================
@app.post("/auth")
def auth(req: AuthReq):
    lic_key = f"license:{req.key}"
    lic_raw = r.get(lic_key)

    if not lic_raw:
        raise HTTPException(401, "Invalid key")

    lic = json.loads(lic_raw)

    if lic["expires_at"] != 0 and time.time() > lic["expires_at"]:
        raise HTTPException(401, "Key expired")

    if lic["hwid"] == "":
        lic["hwid"] = req.hwid
        lic["expires_at"] = key_expire_time(req.key)
        r.set(lic_key, json.dumps(lic))
    elif lic["hwid"] != req.hwid:
        raise HTTPException(401, "HWID mismatch")

    sid = create_session(req.hwid)
    return {"session_id": sid}

@app.post("/get-file")
def get_file(req: FileReq):
    if not validate_session(req.session_id, req.hwid):
        raise HTTPException(403, "Invalid or expired session")

    # одноразовая сессия
    r.delete(f"session:{req.session_id}")

    file_path = "interium.dll"
    if not os.path.exists(file_path):
        raise HTTPException(500, "File not found on server")

    return FileResponse(
        file_path,
        media_type="application/octet-stream",
        filename="interium.dll"
    )

# ================= DEBUG HELPERS =================
@app.post("/debug/add-key/{key}")
def debug_add_key(key: str):
    r.set(
        f"license:{key}",
        json.dumps({"hwid": "", "expires_at": 0})
    )
    return {"status": "ok", "key": key}

# ================= RUN =================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8080)
