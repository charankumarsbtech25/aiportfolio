import os
import sys
from pathlib import Path
import uvicorn

# Ensure the nested portfolio_ai/portfolio_ai directory is in sys.path
ROOT = Path(__file__).resolve().parent
APP_DIR = ROOT / "portfolio_ai" / "portfolio_ai"

sys.path.insert(0, str(APP_DIR))
os.environ["PYTHONPATH"] = str(APP_DIR) + os.pathsep + os.environ.get("PYTHONPATH", "")

if __name__ == "__main__":
    print(f"Starting Portfolio AI server from: {APP_DIR}")
    print("Application URL: http://127.0.0.1:8000/login.html")
    uvicorn.run("api.main:app", host="127.0.0.1", port=8000, reload=True, app_dir=str(APP_DIR))

