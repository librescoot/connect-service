#!/usr/bin/env python3
"""Exercise the installed radio-gaga flow against disposable Sunshine and a password-authenticated TLS broker."""
import argparse
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import tempfile
import time
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sunshine-dir", type=Path, required=True)
    parser.add_argument("--radio-gaga-dir", type=Path, required=True)
    args = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix="connect-installed-test-"))
    connect = Path(__file__).resolve().parents[1]
    sunshine = args.sunshine_dir.resolve()
    radio = args.radio_gaga_dir.resolve()
    for port in (4300, 4301):
        with socket.socket() as check:
            check.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            check.bind(("127.0.0.1", port))
    with socket.socket() as check:
        check.bind(("127.0.0.1", 0))
        broker_port = check.getsockname()[1]
    env = dict(os.environ)
    for key in ("RAILS_MASTER_KEY", "SENTRY_DSN", "DATABASE_URL", "PRIMARY_DATABASE_URL", "QUEUE_DATABASE_URL", "CACHE_DATABASE_URL"):
        env.pop(key, None)
    env.update({"GOTOOLCHAIN": "go1.25.14", "RAILS_ENV": "development", "MQTT_ROLE": "", "CONNECT_ENABLED": "true",
                "CONNECT_BOUNCER_ORIGIN": "http://127.0.0.1:4300", "CONNECT_TEST_DIR": str(root),
                "CONNECT_PROVIDER_TOKEN_FILE": str(root / "provider-token"), "SECRET_KEY_BASE": secrets.token_hex(64),
                "DATABASE_HOST": "127.0.0.1", "DATABASE_USER": "sunshine", "DATABASE_PASSWORD": "sunshine",
                "REDIS_URL": "redis://127.0.0.1:1/15", "MOLLIE_API_KEY": "test_not_used", "MAILER_HOST": "127.0.0.1", "MAILER_PORT": "4301"})
    def private(path, text):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as file:
            file.write(text)
    credential = secrets.token_urlsafe(32)
    private(root / "provider-token", credential)
    private(root / "password", secrets.token_urlsafe(24))
    private(root / "passwords", "")
    private(root / "bouncer-config.json", json.dumps({"origin": "http://127.0.0.1:4300", "providers": [
        {"id": "sunshine", "name": "Sunshine", "origin": "http://127.0.0.1:4301", "profiles": ["radio-gaga/1"], "credential": credential}]}))
    processes = []
    container = "connect-installed-" + secrets.token_hex(5)
    started = False
    def run(command, cwd=sunshine, **options):
        return subprocess.run(command, cwd=cwd, env=env, check=True, **options)
    def start(name, command, cwd):
        fd = os.open(root / (name + ".log"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as log:
            process = subprocess.Popen(command, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            processes.append(process)
            return process
    try:
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=Connect Test CA",
             "-keyout", str(root / "ca.key"), "-out", str(root / "ca.crt")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        run(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=127.0.0.1", "-keyout", str(root / "server.key"),
             "-out", str(root / "server.csr")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        private(root / "extensions", "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n")
        run(["openssl", "x509", "-req", "-days", "1", "-in", str(root / "server.csr"), "-CA", str(root / "ca.crt"),
             "-CAkey", str(root / "ca.key"), "-CAcreateserial", "-extfile", str(root / "extensions"), "-out", str(root / "server.crt")],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        private(root / "mosquitto.conf", f"listener {broker_port} 127.0.0.1\nallow_anonymous false\npassword_file {root}/passwords\ncertfile {root}/server.crt\nkeyfile {root}/server.key\ncafile {root}/ca.crt\npersistence false\n")
        broker = start("mqtt", ["mosquitto", "-c", str(root / "mosquitto.conf")], connect)
        private(root / "broker.json", json.dumps({"port": broker_port, "pid": broker.pid}))
        run(["docker", "run", "-d", "--rm", "--name", container, "--label", "purpose=connect-installed-test", "-e", "POSTGRES_USER=sunshine",
             "-e", "POSTGRES_PASSWORD=sunshine", "-p", "127.0.0.1::5432", "postgis/postgis:17-3.5"], stdout=subprocess.DEVNULL)
        started = True
        for _ in range(60):
            if subprocess.run(["docker", "exec", container, "pg_isready", "-U", "sunshine"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("test database unavailable")
        port = run(["docker", "port", container, "5432/tcp"], capture_output=True, text=True).stdout.strip().rsplit(":", 1)[1]
        env["DATABASE_PORT"] = port
        env["DATABASE_URL"] = f"postgis://sunshine:sunshine@127.0.0.1:{port}/sunshine_connect_development"
        for database in ("sunshine_connect_development", "sunshine_development_queue", "sunshine_development_cache"):
            run(["docker", "exec", container, "psql", "-U", "sunshine", "-d", "postgres", "-c", f"CREATE DATABASE {database} TEMPLATE template0;"], stdout=subprocess.DEVNULL)
        run(["bundle", "exec", "rails", "db:schema:load:primary", "db:schema:load:queue", "db:schema:load:cache", "tailwindcss:build"])
        for name in ("connect", "connect-bouncer"):
            run(["go", "build", "-o", str(root / name), "./cmd/" + name], cwd=connect)
        run(["go", "build", "-o", str(root / "radio-gaga"), "./cmd/radio-gaga"], cwd=radio)
        start("bouncer", [str(root / "connect-bouncer"), "-config", str(root / "bouncer-config.json"), "-state", str(root / "state.json"), "-listen", "127.0.0.1:4300", "-development"], connect)
        start("sunshine", ["bundle", "exec", "ruby", "test/support/connect_server.rb"], sunshine)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for address in ("http://127.0.0.1:4300/pair", "http://127.0.0.1:4301/users/sign_in"):
            for _ in range(100):
                if any(process.poll() is not None for process in processes):
                    raise RuntimeError(f"test service exited; inspect private logs in {root}")
                try:
                    with opener.open(address, timeout=3) as response:
                        if response.status == 200:
                            break
                except OSError:
                    time.sleep(0.5)
            else:
                raise RuntimeError(f"test service not ready; inspect private logs in {root}")
        for mode in ("code", "qr"):
            env["CONNECT_TEST_ENTRY"] = mode
            run(["bundle", "exec", "ruby", "test/support/connect_browser.rb"], timeout=150)
        run(["bundle", "exec", "rails", "runner", 'abort "missing receipts" unless ConnectEnrollment.where.not(completed_at: nil).count == 2; '
             'abort "active claims retained" unless BootstrapToken.active.where(purpose: "connect").count.zero?; puts "PASS: both scoped bootstrap claims completed and were revoked."'])
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
        for process in processes:
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        if started:
            subprocess.run(["docker", "rm", "-f", "-v", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"Test services stopped; private artifacts: {root}")


if __name__ == "__main__":
    main()
