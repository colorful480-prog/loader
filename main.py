from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel
import redis
import uuid
import time
import os
import requests
import base64

app = FastAPI()

# ================= REDIS CONFIG =================
REDIS_URL = os.getenv("REDIS_URL")
r = redis.Redis.from_url(REDIS_URL, decode_responses=True)

LICENSE_PREFIX = "key:license:"
SESSION_TTL = 120
XOR_KEY = 0x47  # 🔐 XOR ключ

# ================== UTILS =================
def key_expire_time(suffix: str) -> int:
    now = int(time.time())
    if suffix == "1": return now + 86400
    if suffix == "2": return now + 1209600
    if suffix == "3": return now + 2592000
    return 0

def create_session(hwid: str) -> str:
    sid = str(uuid.uuid4())
    r.setex(f"session:{sid}", SESSION_TTL, hwid)
    return sid

def validate_session(sid: str, hwid: str) -> bool:
    return r.get(f"session:{sid}") == hwid

def xor_encrypt(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)

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
    try:
        decoded_key  = base64.b64decode(req.key).decode()
        decoded_hwid = base64.b64decode(req.hwid).decode()
    except Exception:
        raise HTTPException(400, "Invalid Base64")

    lic_key = LICENSE_PREFIX + decoded_key

    if not r.exists(lic_key):
        raise HTTPException(401, "Invalid key")

    data = r.hgetall(lic_key)
    hwid_saved = data.get("hwid", "")
    expires_at = int(data.get("expires_at", 0))
    key_suffix = decoded_key[-1]

    if expires_at and time.time() > expires_at:
        raise HTTPException(401, "Key expired")

    if hwid_saved == "":
        r.hset(lic_key, mapping={
            "hwid": decoded_hwid,
            "expires_at": key_expire_time(key_suffix)
        })
    elif hwid_saved != decoded_hwid:
        raise HTTPException(401, "HWID mismatch")

    return {"session_id": create_session(decoded_hwid)}

# 🔥 ОТДАЧА XOR-ЗАШИФРОВАННЫХ БАЙТОВ DLL
@app.post("/get-file")
def get_dll_bytes(req: FileReq):
    try:
        sid  = base64.b64decode(req.session_id).decode()
        hwid = base64.b64decode(req.hwid).decode()
    except Exception:
        raise HTTPException(400, "Invalid Base64")

    if not validate_session(sid, hwid):
        raise HTTPException(403, "Invalid session")

    r.delete(f"session:{sid}")  # одноразовая

    file_path = "interium.dll"

    if not os.path.exists(file_path):
        url = os.getenv("GITHUB_DLL_URL")
        resp = requests.get(url)
        if resp.status_code != 200:
            raise HTTPException(500, "DLL download failed")
        with open(file_path, "wb") as f:
            f.write(resp.content)

    with open(file_path, "rb") as f:
        raw_bytes = f.read()

    encrypted = xor_encrypt(raw_bytes, XOR_KEY)

    return Response(
        content=encrypted,
        media_type="application/octet-stream",
        headers={
            "Cache-Control": "no-store",
            "X-XOR-Key": "0x47"  # можешь убрать, если не нужен
        }
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8080)
