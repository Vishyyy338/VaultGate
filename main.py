"""
VaultGate entrypoint for launching the proxy and upstream service.
"""
import argparse
import os
import threading
import time
import uvicorn

DEFAULT_ADMIN_KEY = "vg_admin_sec_2026_defense"

def load_env_file():
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(env_path):
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip('"').strip("'")
                        if k and k not in os.environ:
                            os.environ[k] = v
        except Exception:
            pass

load_env_file()

def run_upstream(host="127.0.0.1", port=8000):
    from upstream_mock import app as upstream_app
    print(f"Starting upstream server on http://{host}:{port}")
    uvicorn.run(upstream_app, host=host, port=port, log_level="warning")

def run_proxy(host="0.0.0.0", port=8080):
    import logging
    from proxy import ConsolePollingFilter, app as proxy_app
    logging.getLogger("uvicorn.access").addFilter(ConsolePollingFilter())
    print(f"Starting VaultGate proxy on http://{host}:{port}")
    display_host = "localhost" if host == "0.0.0.0" else host
    print(f"Console available at http://{display_host}:{port}/vaultgate/console")
    admin_key = os.environ.get("VAULTGATE_ADMIN_KEY", DEFAULT_ADMIN_KEY)
    print(f"Console Operator API Key: {admin_key}")
    uvicorn.run(proxy_app, host=host, port=port, log_level="info")

def main():
    parser = argparse.ArgumentParser(description="VaultGate Security Proxy")
    parser.add_argument("--mode", choices=["all", "proxy", "upstream"], default="all",
                        help="Service mode (default: all)")
    parser.add_argument("--proxy-host", type=str, default=os.environ.get("VAULTGATE_PROXY_HOST", "0.0.0.0"),
                        help="VaultGate proxy listen host (default: 0.0.0.0)")
    parser.add_argument("--proxy-port", type=int, default=int(os.environ.get("VAULTGATE_PROXY_PORT", 8080)),
                        help="VaultGate proxy port (default: 8080)")
    parser.add_argument("--upstream-host", type=str, default=os.environ.get("VAULTGATE_UPSTREAM_HOST", "127.0.0.1"),
                        help="Upstream listen host (default: 127.0.0.1)")
    parser.add_argument("--upstream-port", type=int, default=int(os.environ.get("VAULTGATE_UPSTREAM_PORT", 8000)),
                        help="Upstream port (default: 8000)")
    parser.add_argument("--admin-key", type=str, default=os.environ.get("VAULTGATE_ADMIN_KEY", DEFAULT_ADMIN_KEY),
                        help="Operator API Key for accessing console")

    args = parser.parse_args()
    os.environ["VAULTGATE_ADMIN_KEY"] = args.admin_key
    if "VAULTGATE_UPSTREAM_URL" not in os.environ:
        os.environ["VAULTGATE_UPSTREAM_URL"] = f"http://{args.upstream_host}:{args.upstream_port}"

    if args.mode == "upstream":
        run_upstream(host=args.upstream_host, port=args.upstream_port)
    elif args.mode == "proxy":
        run_proxy(host=args.proxy_host, port=args.proxy_port)
    else:
        upstream_thread = threading.Thread(
            target=run_upstream, 
            args=(args.upstream_host, args.upstream_port), 
            daemon=True
        )
        upstream_thread.start()
        time.sleep(1.0)
        run_proxy(host=args.proxy_host, port=args.proxy_port)

if __name__ == "__main__":
    main()
