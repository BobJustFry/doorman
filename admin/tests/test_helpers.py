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


def test_helper_does_not_follow_a_symlink_planted_by_the_container(tmp_path):
    """The data directory belongs to the container. A link ban-status.json -> /etc/shadow
    must not let the root helper overwrite the target."""
    import os
    import pytest
    mod = load("bans_helper3", "fail2ban-bans.py")
    victim = tmp_path / "victim.txt"
    victim.write_text("precious")
    data = tmp_path / "data"
    data.mkdir()
    try:
        os.symlink(victim, data / "ban-status.json")
        os.symlink(victim, data / "manual-bans.json")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available here")
    mod.apply(str(data), FakeFail2ban())
    assert victim.read_text() == "precious"
    assert not (data / "ban-status.json").is_symlink()
    assert "jails" in json.loads((data / "ban-status.json").read_text())
    assert [p.name for p in data.iterdir() if p.name.startswith(".tmp-")] == []


def test_egress_plan_allows_only_route_upstreams_before_rejecting_private_networks():
    mod = load("fw_sync", "firewall-sync.py")
    data = {"tcp": [8444, "x", 80], "upstreams": [
        "192.168.12.20:443", "192.168.12.20:8444", "8.8.8.8:443", "127.0.0.1:8080", "nas.lan:5000", "bad"]}
    names = {"nas.lan": {"192.168.12.30"}}
    ups, unresolved = mod.wanted_upstreams(data, resolver=lambda h: names.get(h, mod.resolve(h)))
    assert ups == {("192.168.12.20", 443), ("192.168.12.20", 8444), ("192.168.12.30", 5000)}
    assert unresolved == 0
    assert mod.wanted_ports(data) == {8444}  # privileged and junk values are dropped
    plan = mod.egress_plan(ups, {("192.168.12.1", 53, "udp")}, v6=False)
    kinds = [r[0] for r in plan]
    assert kinds == sorted(kinds)  # every "allow" comes before any "reject"
    assert ["allow", "out", "proto", "tcp", "to", "192.168.12.20", "port", "8444", "comment", "doorman-egress"] in plan
    assert ["reject", "out", "to", "192.168.0.0/16", "comment", "doorman-egress"] in plan
    assert not any("fc00::/7" in r for r in plan)  # IPv6 rules only when ufw handles IPv6
    assert all(r[-1] == "doorman-egress" for r in plan)


def test_egress_unresolved_name_is_reported():
    mod = load("fw_sync2", "firewall-sync.py")
    ups, unresolved = mod.wanted_upstreams({"upstreams": ["gone.lan:80"]}, resolver=lambda h: set())
    assert ups == set() and unresolved == 1
