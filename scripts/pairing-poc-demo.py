#!/usr/bin/env python3
"""Run the three-component demonstration with a disposable local PostGIS container."""
import argparse
import hashlib
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
    parser.add_argument("--sunshine-dir", required=True, type=Path)
    parser.add_argument("--smoke", action="store_true", help="run headless Chrome and exit")
    args = parser.parse_args()
    sunshine = args.sunshine_dir.resolve()
    if not (sunshine / "script/connect_poc_smoke.rb").is_file():
        parser.error("Sunshine working copy must contain the pairing proof of concept")
    connect = Path(__file__).resolve().parents[1]
    for port in (4300, 4301):
        with socket.socket() as listener:
            try:
                listener.bind(("127.0.0.1", port))
            except OSError:
                parser.error(f"loopback port {port} is already in use; leave the existing service untouched")
    root = Path(tempfile.mkdtemp(prefix="connect-pairing-poc-"))
    container = "connect-poc-" + hashlib.sha256(str(root).encode()).hexdigest()[:12]
    env = dict(os.environ)
    for key in ("RAILS_MASTER_KEY", "SENTRY_DSN", "DATABASE_URL", "PRIMARY_DATABASE_URL", "QUEUE_DATABASE_URL", "CACHE_DATABASE_URL"):
        env.pop(key, None)
    env.update({
        "GOTOOLCHAIN": "go1.25.14", "RAILS_ENV": "development", "MQTT_ROLE": "",
        "CONNECT_POC_ENABLED": "1", "CONNECT_POC_BOUNCER": "http://127.0.0.1:4300",
        "CONNECT_POC_SUNSHINE": "http://127.0.0.1:4301",
        "CONNECT_POC_PROVIDER_TOKEN": secrets.token_urlsafe(32),
        "SECRET_KEY_BASE": secrets.token_hex(64), "MOLLIE_API_KEY": "test_poc_not_used",
        "DATABASE_HOST": "127.0.0.1", "DATABASE_USER": "sunshine", "DATABASE_PASSWORD": "sunshine",
        "REDIS_URL": "redis://127.0.0.1:1/15",
        "MAILER_HOST": "127.0.0.1", "MAILER_PORT": "4301",
        "CONNECT_POC_EMAIL": "pairing@example.test", "CONNECT_POC_PASSWORD_FILE": str(root / "password"),
        "CONNECT_POC_DEVICE": str(root / "connect-poc-device"),
        "CONNECT_POC_DEVICE_STATE": str(root / "scooter"),
    })
    fd = os.open(root / "password", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as password:
        password.write(secrets.token_urlsafe(24))
    processes = []
    started_db = False

    def run(command, cwd=sunshine, **kwargs):
        return subprocess.run(command, cwd=cwd, env=env, check=True, **kwargs)

    def start(name, command, cwd):
        fd = os.open(root / (name + ".log"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as log:
            processes.append(subprocess.Popen(command, cwd=cwd, env=env, stdout=log,
                                              stderr=subprocess.STDOUT, start_new_session=True))

    try:
        run(["docker", "run", "-d", "--rm", "--name", container, "--label", "purpose=connect-pairing-poc",
             "-e", "POSTGRES_USER=sunshine", "-e", "POSTGRES_PASSWORD=sunshine",
             "-p", "127.0.0.1::5432", "postgis/postgis:17-3.5"], stdout=subprocess.DEVNULL)
        started_db = True
        for _ in range(60):
            ready = subprocess.run(["docker", "exec", container, "pg_isready", "-U", "sunshine"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if ready.returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("disposable database did not start")
        port = run(["docker", "port", container, "5432/tcp"], capture_output=True, text=True).stdout.strip().rsplit(":", 1)[1]
        env["DATABASE_PORT"] = port
        env["DATABASE_URL"] = f"postgis://sunshine:sunshine@127.0.0.1:{port}/sunshine_pairing_poc_development"
        for database in ("sunshine_pairing_poc_development", "sunshine_development_queue", "sunshine_development_cache"):
            run(["docker", "exec", container, "psql", "-U", "sunshine", "-d", "postgres", "-c",
                 f"CREATE DATABASE {database} TEMPLATE template0;"], stdout=subprocess.DEVNULL)
        run(["bundle", "exec", "rails", "db:schema:load:primary", "db:schema:load:queue", "db:schema:load:cache", "tailwindcss:build"])
        run(["bundle", "exec", "rails", "runner", "script/connect_poc_seed.rb"])
        for name in ("connect-poc-device", "connect-poc-bouncer"):
            run(["go", "build", "-o", str(root / name), "./cmd/" + name], cwd=connect)
        start("bouncer", [str(root / "connect-poc-bouncer"), "-state", str(root / "bouncer/state.json")], connect)
        start("sunshine", ["bundle", "exec", "rails", "server", "-b", "127.0.0.1", "-p", "4301", "-P", str(root / "sunshine.pid")], sunshine)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for address in (env["CONNECT_POC_BOUNCER"] + "/pair", env["CONNECT_POC_SUNSHINE"] + "/users/sign_in"):
            for _ in range(80):
                if any(process.poll() is not None for process in processes):
                    raise RuntimeError(f"service exited; inspect private logs in {root}")
                try:
                    with opener.open(address, timeout=3) as response:
                        if response.status == 200:
                            break
                except OSError:
                    if any(process.poll() is not None for process in processes):
                        raise RuntimeError(f"service exited; inspect private logs in {root}")
                    time.sleep(0.5)
            else:
                raise RuntimeError(f"service did not become ready; inspect private logs in {root}")
        if args.smoke:
            for mode in ("code", "qr"):
                env["CONNECT_POC_USE_QR"] = "1" if mode == "qr" else "0"
                env["CONNECT_POC_DEVICE_STATE"] = str(root / ("scooter-" + mode))
                run(["bundle", "exec", "ruby", "script/connect_poc_smoke.rb"], timeout=120)
            run(["bundle", "exec", "rails", "runner",
                 'abort "missing receipt" unless ConnectPocEnrollment.where.not(connected_at: nil).exists?; '
                 'abort "real scooter created" unless Scooter.count.zero?; '
                 'puts "PASS: account-bound receipt persisted; no real scooters created."'])
        else:
            print(f"\nLocal demo is running. Private disposable state: {root}", flush=True)
            print(f"Login: pairing@example.test; password is in {root / 'password'}", flush=True)
            for command in ("register", "code", "wait", "status"):
                print(f"{root / 'connect-poc-device'} -state-dir {root / 'scooter'} {command}", flush=True)
            print("Open http://127.0.0.1:4300/pair after requesting a code. Ctrl-C stops the demo and removes its database.", flush=True)
            while all(process.poll() is None for process in processes):
                time.sleep(1)
            raise RuntimeError("a local demo service exited")
    except KeyboardInterrupt:
        pass
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
        if started_db:
            subprocess.run(["docker", "rm", "-f", "-v", container], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"Disposable files retained privately in {root}; no demo service remains running.")


if __name__ == "__main__":
    main()
