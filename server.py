import os
import sys
import uvicorn

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Ensure workspace root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

if __name__ == "__main__":
    print("🛡️ Starting CyberTriage AI SOC Server on http://127.0.0.1:8000 ...")
    uvicorn.run("api.server:app", host="127.0.0.1", port=8000, reload=True, app_dir=PROJECT_ROOT)
