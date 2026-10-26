"""The root helpers on the host are plain scripts; test them with a fake fail2ban."""
import importlib.util
import json
import time
from pathlib import Path

DEPLOY = Path(__file__).resolve().parents[2] / "deploy"


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, DEPLOY / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeFail2ban:
    def __init__(self, **jails):
        self.jails = {j: list(ips) for j, ips in jails.items()}
        self.calls = []

    def __call__(self, *args):
        self.calls.append(args)
        if args[0] == "status":
            ips = self.jails.get(args[1], [])
            return f"Status for the jail: {args[1]}\n   `- Banned IP list:\t{' '.join(ips)}\n"
        if args[:1] == ("set",):
            _, jail, action, ip = args
            ips = self.jails.setdefault(jail, [])
            if action == "banip" and ip not in ips:
                ips.append(ip)
            if action == "unbanip" and ip in ips:
                ips.remove(ip)
        return ""


def write(tmp_path, bans=(), unban=()):
    (tmp_path / "manual-bans.json").write_text(json.dumps(
        {"bans": [{"ip": ip} for ip in bans], "unban": [{"ip": ip, "ts": time.time()} for ip in unban]}))


def test_helper_blocks_and_unblocks_the_manual_jail(tmp_path):
    mod = load("bans_helper", "fail2ban-bans.py")
    f2b = FakeFail2ban(**{"doorman-manual": ["1.1.1.1"]})
    write(tmp_path, bans=["8.8.4.4"])
    log = mod.apply(str(tmp_path), f2b)
    assert f2b.jails["doorman-manual"] == ["8.8.4.4"]
    assert "blocked 8.8.4.4" in log and "unblocked 1.1.1.1 (manual)" in log
    status = json.loads((tmp_path / "ban-status.json").read_text())
    assert status["jails"]["doorman-manual"] == ["8.8.4.4"] and time.time() - status["updated"] < 5


def test_helper_lifts_automatic_jail_blocks_on_request(tmp_path):
    mod = load("bans_helper2", "fail2ban-bans.py")
    f2b = FakeFail2ban(**{"doorman-stub": ["8.8.4.4", "8.8.8.8"], "doorman-probe": ["8.8.4.4"]})
    write(tmp_path, unban=["8.8.4.4"])
    mod.apply(str(tmp_path), f2b)
    assert f2b.jails["doorman-stub"] == ["8.8.8.8"] and f2b.jails["doorman-probe"] == []


def test_helper_never_trusts_the_file(tmp_path):
    mod = load("bans_helper3", "fail2ban-bans.py")
    f2b = FakeFail2ban()
    (tmp_path / "manual-bans.json").write_text(json.dumps({"bans": [
        {"ip": "192.168.1.5"}, {"ip": "127.0.0.1"}, {"ip": "10.0.0.1"}, {"ip": "224.0.0.1"},
        {"ip": "8.8.4.4; reboot"}, {"ip": "$(id)"}, "8.8.8.8", {"ip": "9.9.9.9"}]}))
    mod.apply(str(tmp_path), f2b)
    assert f2b.jails["doorman-manual"] == ["9.9.9.9"]  # everything private, malformed or injected is dropped
    (tmp_path / "manual-bans.json").write_text("not json")
    mod.apply(str(tmp_path), f2b)  # garbage must not crash the helper
    (tmp_path / "manual-bans.json").write_text("[1, 2]")
    mod.apply(str(tmp_path), f2b)


def test_stale_unban_requests_are_ignored(tmp_path):
    mod = load("bans_helper4", "fail2ban-bans.py")
    f2b = FakeFail2ban(**{"doorman-stub": ["8.8.4.4"]})
    (tmp_path / "manual-bans.json").write_text(json.dumps({"bans": [], "unban": [{"ip": "8.8.4.4", "ts": time.time() - 3600}]}))
    mod.apply(str(tmp_path), f2b)
    assert f2b.jails["doorman-stub"] == ["8.8.4.4"]  # an old request must not undo a later automatic ban


def test_installer_and_filters_are_consistent():
    jail = (DEPLOY / "fail2ban" / "jail.doorman.conf").read_text()
    for name in ("doorman-auth", "doorman-stub", "doorman-probe", "doorman-manual"):
        assert f"[{name}]" in jail
    installer = (DEPLOY / "install-fail2ban.sh").read_text()
    assert "doorman-fail2ban-bans" in installer and "doorman-bans.path" in installer
    for f in ("auth", "stub", "probe"):
        assert (DEPLOY / "fail2ban" / "filter.d" / f"doorman-{f}.conf").exists()
