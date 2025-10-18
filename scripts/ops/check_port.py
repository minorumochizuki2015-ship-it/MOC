import socket
import subprocess
import sys


def is_port_in_use(port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", port))
        return False
    except OSError:
        return True
    finally:
        s.close()


def show_netstat(port: int) -> None:
    try:
        # Use PowerShell to filter netstat output by port
        cmd = [
            "powershell",
            "-NoLogo",
            "-NoProfile",
            "-Command",
            f"netstat -ano | Select-String -Pattern ':{port}\\s'",
        ]
        out = subprocess.check_output(cmd, text=True)
        print(out)
    except Exception as e:
        print(f"[check_port] Netstat check failed: {e}")


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    if is_port_in_use(port):
        print(f"[check_port] PORT {port} appears in use.")
        show_netstat(port)
        sys.exit(1)
    else:
        print(f"[check_port] PORT {port} free.")
        sys.exit(0)


if __name__ == "__main__":
    main()
