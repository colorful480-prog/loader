from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.responses import FileResponse
import json, uuid, time, os, requests

app = FastAPI()

# --- Gist Settings ---
GITHUB_TOKEN = "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"
GIST_ID = "16ab9ab4ed573f30b04aa2cf2e20de47"
GIST_FILE = "atl_keys.txt"  # можно оставить txt, но содержимое будет JSON

SESSIONS = {}
SESSION_TTL = 120

# ---------------- Gist Functions ----------------
def load_licenses():
    """Скачать JSON с Gist"""
    r = requests.get(
        f"https://api.github.com/gists/{GIST_ID}",
        headers={"Authorization": f"token {GITHUB_TOKEN}"}
    )
    r.raise_for_status()
    content = r.json()["files"][GIST_FILE]["content"]
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        return {}

def save_licenses(licenses: dict):
    """Сохранить JSON в Gist"""
    content = json.dumps(licenses, indent=4)
    r = requests.patch(
        f"https://api.github.com/gists/{GIST_ID}",
        headers={"Authorization": f"token {GITHUB_TOKEN}"},
        json={"files": {GIST_FILE: {"content": content}}}
    )
    r.raise_for_status()

# ---------------- Utils ----------------
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
    SESSIONS[sid] = {
        "hwid": hwid,
        "expires": time.time() + SESSION_TTL
    }
    return sid

def validate_session(sid: str, hwid: str) -> bool:
    s = SESSIONS.get(sid)
    if not s:
        return False
    if time.time() > s["expires"]:
        del SESSIONS[sid]
        return False
    if s["hwid"] != hwid:
        return False
    return True

# ---------------- Models ----------------
class AuthReq(BaseModel):
    key: str
    hwid: str

class FileReq(BaseModel):
    session_id: str
    hwid: str

# ---------------- Routes ----------------
@app.post("/auth")
def auth(req: AuthReq):
    licenses = load_licenses()

    lic = licenses.get(req.key)
    if not lic:
        raise HTTPException(401, "Invalid key")

    if lic["expires_at"] != 0 and time.time() > lic["expires_at"]:
        raise HTTPException(401, "Key expired")

    if lic["hwid"] == "":
        lic["hwid"] = req.hwid
        lic["expires_at"] = key_expire_time(req.key)
        save_licenses(licenses)
    elif lic["hwid"] != req.hwid:
        raise HTTPException(401, "HWID mismatch")

    sid = create_session(req.hwid)
    return {"session_id": sid}

@app.post("/get-file")
def get_file(req: FileReq):
    if not validate_session(req.session_id, req.hwid):
        raise HTTPException(403, "Invalid or expired session")

    del SESSIONS[req.session_id]

    file_path = "interium.dll"

    if not os.path.exists(file_path):
        raise HTTPException(500, "File not found on server")

    return FileResponse(
        file_path,
        media_type="application/octet-stream",
        filename="interium.dll"
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8080)
