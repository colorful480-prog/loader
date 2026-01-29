from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.responses import FileResponse
import redis
import uuid
import time
import os
import requests

app = FastAPI()

# ================= REDIS CONFIG =================
REDIS_URL = os.getenv("REDIS_URL")
if not REDIS_URL:
    raise RuntimeError("REDIS_URL not set")

r = redis.Redis.from_url(REDIS_URL, decode_responses=True)

LICENSE_PREFIX = "key:license:"
SESSION_TTL = 120

# ================== UTILS =================
def key_expire_time(suffix: str) -> int:
    now = int(time.time())
    if suffix == "1": return now + 86400       # 1 день
    if suffix == "2": return now + 1209600     # 2 недели
    if suffix == "3": return now + 2592000     # месяц
    return 0

def create_session(hwid: str) -> str:
    sid = str(uuid.uuid4())
    r.setex(f"session:{sid}", SESSION_TTL, hwid)
    return sid

def validate_session(sid: str, hwid: str) -> bool:
    stored_hwid = r.get(f"session:{sid}")
    return stored_hwid == hwid

# ================== MODELS =================
class AuthReq(BaseModel):
    key: str
    hwid: str

class FileReq(BaseModel):
    session_id: str
    hwid: str

# ================== ROUTES =================
@app.post("/auth")
def auth(req: AuthReq):
    lic_key = LICENSE_PREFIX + req.key

    if not r.exists(lic_key):
        raise HTTPException(401, "Invalid key")

    data = r.hgetall(lic_key)
    if not data:
        raise HTTPException(401, "Invalid key structure in Redis")

    hwid_saved = data.get("hwid", "")
    expires_at = int(data.get("expires_at", 0))
    key_suffix = req.key[-1] if req.key else "0"

    # Проверка срока действия
    if expires_at != 0 and time.time() > expires_at:
        raise HTTPException(401, "Key expired")

    # Активация ключа
    if hwid_saved == "":
        r.hset(lic_key, mapping={
            "hwid": req.hwid,
            "expires_at": key_expire_time(key_suffix)
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

    # --- путь к файлу на сервере ---
    file_path = "interium.dll"

    # --- если файла нет, скачать его с репозитория ---
    if not os.path.exists(file_path):
        github_url = os.getenv("GITHUB_DLL_URL")
        github_token = os.getenv("GITHUB_TOKEN")
        if not github_url:
            raise HTTPException(500, "DLL URL not set")

        headers = {}
        if github_token:
            headers["Authorization"] = f"token {github_token}"

        try:
            resp = requests.get(github_url, headers=headers)
            if resp.status_code != 200:
                raise HTTPException(500, f"Failed to download DLL: {resp.status_code}")
            with open(file_path, "wb") as f:
                f.write(resp.content)
        except Exception as e:
            raise HTTPException(500, f"Failed to download DLL: {e}")

    return FileResponse(
        file_path,
        media_type="application/octet-stream",
        filename="interium.dll",
        headers={"Cache-Control": "no-store"}
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8080)
