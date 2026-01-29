from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.responses import FileResponse
import redis
import uuid
import time
import os

app = FastAPI()

# ================= REDIS CONFIG =================

REDIS_URL = os.getenv("REDIS_URL")
if not REDIS_URL:
    raise RuntimeError("REDIS_URL not set")

r = redis.Redis.from_url(
    REDIS_URL,
    decode_responses=True
)

SESSION_TTL = 120  # секунд

# ================= UTILS =================

def key_expire_time(key: str) -> int:
    now = int(time.time())
    if not key or not key[-1].isdigit():
        return 0

    if key[-1] == "1":
        return now + 86400        # 1 день
    if key[-1] == "2":
        return now + 604800       # 7 дней
    if key[-1] == "3":
        return now + 2592000      # 30 дней

    return 0


def create_session(hwid: str) -> str:
    sid = str(uuid.uuid4())
    r.hset(f"session:{sid}", mapping={
        "hwid": hwid
    })
    r.expire(f"session:{sid}", SESSION_TTL)
    return sid


def validate_session(sid: str, hwid: str) -> bool:
    key = f"session:{sid}"

    if not r.exists(key):
        return False

    stored_hwid = r.hget(key, "hwid")
    return stored_hwid == hwid


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

    if not r.exists(lic_key):
        raise HTTPException(401, "Invalid key")

    expires_at = int(r.hget(lic_key, "expires_at") or 0)
    hwid_saved = r.hget(lic_key, "hwid") or ""

    if expires_at != 0 and time.time() > expires_at:
        raise HTTPException(401, "Key expired")

    if hwid_saved == "":
        r.hset(lic_key, mapping={
            "hwid": req.hwid,
            "expires_at": key_expire_time(req.key)
        })
    elif hwid_saved != req.hwid:
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


# ================= DEBUG / ADMIN =================

@app.post("/debug/add-key/{key}")
def debug_add_key(key: str):
    r.hset(f"license:{key}", mapping={
        "hwid": "",
        "expires_at": 0
    })
    return {"status": "ok", "key": key}


@app.get("/debug/all-keys")
def debug_all_keys():
    keys = r.keys("license:*")
    return {"keys": keys}


# ================= RUN =================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8080)
