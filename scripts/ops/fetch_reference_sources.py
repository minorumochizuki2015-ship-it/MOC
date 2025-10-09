import json
import os
import subprocess
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

CONFIG_PATH = Path("scripts/ops/fetch_sources_config.json")


def fetch_web(url: str, dest_dir: Path, filename: str):
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / filename
    # Add a UA header to avoid 403 from sites like Wikipedia
    req = Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (compatible; TraeFetcher/1.0; +https://example.local)"},
    )
    with urlopen(req) as r:
        content = r.read()
    with open(dest, "wb") as f:
        f.write(content)
    print(f"[web] saved: {dest}")


def fetch_git(url: str, dest_dir: Path):
    dest_dir.mkdir(parents=True, exist_ok=True)
    if (dest_dir / ".git").exists():
        subprocess.run(["git", "-C", str(dest_dir), "pull"], check=False)
        print(f"[git] pulled: {dest_dir}")
    else:
        subprocess.run(["git", "clone", url, str(dest_dir)], check=False)
        print(f"[git] cloned: {url} -> {dest_dir}")


def main():
    if not CONFIG_PATH.exists():
        print(f"config not found: {CONFIG_PATH}")
        return
    cfg = json.loads(Path(CONFIG_PATH).read_text(encoding="utf-8"))
    sources = cfg.get("sources", [])
    for s in sources:
        url = s.get("url") or ""
        name = s.get("name")
        if not url:
            print(f"skip '{name}' — url is empty")
            continue
        dest_dir = Path(s.get("dest_dir"))
        typ = s.get("type")
        try:
            if typ == "web":
                filename = s.get("filename") or "download.bin"
                fetch_web(url, dest_dir, filename)
            elif typ == "git":
                fetch_git(url, dest_dir)
            else:
                print(f"unknown type: {typ}")
        except HTTPError as e:
            print(f"[error] {name}: HTTP {e.code} for {url}")
        except URLError as e:
            print(f"[error] {name}: URL error {e.reason} for {url}")
        except Exception as e:
            print(f"[error] {name}: {e}")


if __name__ == "__main__":
    main()
