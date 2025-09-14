import sys
from pathlib import Path

if __name__ == "__main__":
    repo = Path(__file__).resolve().parent
    print("exe:", sys.executable)
    print(".venv exists:", (repo / ".venv" / "Scripts" / "python.exe").exists())
