from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.responses import FileResponse
import json, uuid, time, os

app = FastAPI()

LICENSE_FILE = "licenses.json"
SESSIONS = {}  # session_id -> {hwid, expires}
SESSION_TTL = 120  # TTL сессии в секундах

# ---------- utils ----------
def load_licenses():
    if not os.path.exists(LICENSE_FILE):
        return {}
    with open(LICENSE_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}

def save_licenses(licenses):
    with open(LICENSE_FILE, "w") as f:
        json.dump(licenses, f, indent=4)

def create_session(hwid):
    sid = str(uuid.uuid4())
    SESSIONS[sid] = {
        "hwid": hwid,
        "expires": time.time() + SESSION_TTL
    }
    return sid

def validate_session(sid, hwid):
    s = SESSIONS.get(sid)
    if not s:
        return False
    if time.time() > s["expires"]:
        del SESSIONS[sid]
        return False
    if s["hwid"] != hwid:
        return False
    return True

# ---------- models ----------
class AuthReq(BaseModel):
    key: str
    hwid: str

class FileReq(BaseModel):
    session_id: str
    hwid: str

# ---------- endpoints ----------
@app.post("/auth")
def auth(req: AuthReq):
    licenses = load_licenses()

    if req.key not in licenses:
        raise HTTPException(401, "Invalid key")

    # Привязываем HWID при первом использовании
    if licenses[req.key] == "":
        licenses[req.key] = req.hwid
        save_licenses(licenses)
    elif licenses[req.key] != req.hwid:
        raise HTTPException(401, "HWID mismatch")

    sid = create_session(req.hwid)
    return {"session_id": sid}

@app.post("/get-file")
def get_file(req: FileReq):
    if not validate_session(req.session_id, req.hwid):
        raise HTTPException(403, "Invalid or expired session")

    # одноразовая сессия
    del SESSIONS[req.session_id]

    return FileResponse(
        "test.txt",
        media_type="text/plain",
        filename="test.txt"
    )

# ---------- запуск ----------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="192.168.31.64", port=28015)
