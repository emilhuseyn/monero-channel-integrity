"""Census of the channels that ship Monero: what each one pins, and whether the pin
matches the release binaryFate signed.

Usage: py channel_census.py [--json out.json]
Needs gpg on PATH. Set GITHUB_TOKEN to avoid the unauthenticated API limit.
"""
import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request

RAW = "https://raw.githubusercontent.com"
HASHES_URL = "https://www.getmonero.org/downloads/hashes.txt"
KEY_URL = f"{RAW}/monero-project/monero/master/utils/gpg_keys/binaryfate.asc"
BINARYFATE_FPR = "81AC591FE9C4B65C5806AFC3F0AF4D462A0BDF92"


def fetch(url, api=False):
    req = urllib.request.Request(url, headers={"User-Agent": "monero-channel-census"})
    if api and os.environ.get("GITHUB_TOKEN"):
        req.add_header("Authorization", "Bearer " + os.environ["GITHUB_TOKEN"])
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8", "replace")


def gh(path):
    return json.loads(fetch("https://api.github.com/" + path, api=True))


def signed_hashes():
    """Return {filename: sha256} from hashes.txt after checking binaryFate's signature."""
    text = fetch(HASHES_URL)
    with tempfile.TemporaryDirectory() as home:
        env = dict(os.environ, GNUPGHOME=home)
        key = os.path.join(home, "binaryfate.asc")
        msg = os.path.join(home, "hashes.txt")
        open(key, "w").write(fetch(KEY_URL))
        open(msg, "w").write(text)
        subprocess.run(["gpg", "--batch", "--import", key], env=env, capture_output=True)
        out = subprocess.run(["gpg", "--batch", "--status-fd", "1", "--verify", msg],
                             env=env, capture_output=True, text=True).stdout
    if f"VALIDSIG {BINARYFATE_FPR}" not in out:
        sys.exit("hashes.txt signature did not verify against binaryFate's key")
    return {m.group(2): m.group(1) for m in re.finditer(r"^([0-9a-f]{64})\s+(\S+)$", text, re.M)}


def match(signed, name, h):
    if name not in signed:
        return "not in current signed list"
    return "MATCH" if signed[name] == h else "MISMATCH"


def arch(pkg):
    t = fetch(f"https://gitlab.archlinux.org/archlinux/packaging/packages/{pkg}/-/raw/main/PKGBUILD")
    v = re.search(r"^pkgver=(\S+)", t, re.M).group(1)
    sig = "?signed#tag=" in t and "validpgpkeys" in t
    return dict(version=v, ships="source (git tag)",
                trust="makepkg verifies the tag signature (validpgpkeys)" if sig else "unsigned git ref",
                pin_check="n/a (signature checked at build)")


def homebrew_formula(signed):
    t = fetch(f"{RAW}/Homebrew/homebrew-core/master/Formula/m/monero.rb")
    url, h = re.search(r'url "([^"]+)"\s+sha256 "([0-9a-f]{64})"', t).groups()
    v = re.search(r"v([\d.]+)\.tar", url).group(1)
    who = gh("repos/Homebrew/homebrew-core/commits?path=Formula/m/monero.rb&per_page=5")
    bump = next((c["commit"]["author"]["name"] for c in who
                 if re.fullmatch(r"monero [\d.]+", c["commit"]["message"].split("\n")[0])), "?")
    return dict(version=v, ships="source tarball", trust=f"sha256 pin, last version bump by {bump}",
                pin_check=match(signed, url.rsplit("/", 1)[1], h))


def homebrew_cask(signed):
    t = fetch(f"{RAW}/Homebrew/homebrew-cask/master/Casks/m/monero-wallet.rb")
    v = re.search(r'version "([^"]+)"', t).group(1)
    arm = re.search(r'arm:\s+"([0-9a-f]{64})"', t).group(1)
    intel = re.search(r'intel:\s+"([0-9a-f]{64})"', t).group(1)
    r = [match(signed, f"monero-gui-mac-armv8-v{v}.dmg", arm), match(signed, f"monero-gui-mac-x64-v{v}.dmg", intel)]
    return dict(version=v, ships="upstream binary (dmg)", trust="sha256 pin, bot-bumped",
                pin_check="MATCH" if set(r) == {"MATCH"} else "/".join(r))


def flathub(signed):
    t = fetch(f"{RAW}/flathub/org.getmonero.Monero/master/org.getmonero.Monero.yaml")
    url, h = re.search(r"url: (https://downloads\.getmonero\.org/gui/monero-gui-source-v[\d.]+\.tar\.bz2)\s+sha256: ([0-9a-f]{64})", t).groups()
    v = re.search(r"v([\d.]+)\.tar", url).group(1)
    auto = "x-checker-data" in t
    return dict(version=v, ships="source tarball",
                trust="sha256 pin, refreshed by flatpak-external-data-checker" if auto else "sha256 pin",
                pin_check=match(signed, url.rsplit("/", 1)[1], h))


def scoop(signed):
    d = json.loads(fetch(f"{RAW}/ScoopInstaller/Extras/master/bucket/monero.json"))
    a = d["architecture"]["64bit"]
    src = d.get("autoupdate", {}).get("hash", {}).get("url", "")
    return dict(version=d["version"], ships="upstream binary (GUI zip)",
                trust=f"hash pin, autoupdate scrapes it from {src.replace('$version', '<v>')}",
                pin_check=match(signed, a["url"].rsplit("/", 1)[1], a["hash"]))


def nix(attr):
    t = fetch(f"{RAW}/NixOS/nixpkgs/master/pkgs/by-name/mo/{attr}/package.nix")
    v = re.search(r'version = "([^"]+)"', t).group(1)
    return dict(version=v, ships="source (GitHub tag)", trust="NAR hash of the tag, no signature check",
                pin_check="n/a (not a release artefact)")


def docker():
    t = fetch(f"{RAW}/sethforprivacy/simple-monerod-docker/main/Dockerfile")
    v = re.search(r"ARG MONERO_BRANCH=v(\S+)", t).group(1)
    pinned = re.search(r"ARG MONERO_COMMIT_HASH=([0-9a-f]{40})", t).group(1)
    ref = gh(f"repos/monero-project/monero/git/ref/tags/v{v}")["object"]
    commit = gh(f"repos/monero-project/monero/git/tags/{ref['sha']}")["object"]["sha"] if ref["type"] == "tag" else ref["sha"]
    return dict(version=v, ships="source (git clone, sethforprivacy/simple-monerod)",
                trust="commit hash checked at build, tag signature not checked",
                pin_check="MATCH (tag commit)" if commit == pinned else "MISMATCH (tag commit)")


def guix():
    t = fetch("https://codeberg.org/guix/guix/raw/branch/master/gnu/packages/finance.scm")
    v = re.search(r'\(define-public monero\n.*?\(version "([^"]+)"\)', t, re.S).group(1)
    return dict(version=v, ships="source (git tag)", trust="NAR hash of the tag, no signature check",
                pin_check="n/a (not a release artefact)")


def debian():
    d = json.loads(fetch("https://sources.debian.org/api/src/monero/"))
    rows = []
    for x in d["versions"]:
        for s in x["suites"]:
            rows.append((s, x["version"].split("+")[0]))
    return rows


def freebsd():
    t = fetch(f"{RAW}/freebsd/freebsd-ports/main/net-p2p/monero-cli/Makefile")
    v = re.search(r"^DISTVERSION=\s*(\S+)", t, re.M).group(1)
    return dict(version=v, ships="source (GitHub tarball)", trust="distinfo sha256, no signature check",
                pin_check="n/a (not a release artefact)")


def chocolatey():
    t = fetch("https://community.chocolatey.org/api/v2/Packages()?$filter=Id%20eq%20'monero'%20and%20IsLatestVersion")
    v = re.search(r"<d:Version>([^<]+)</d:Version>", t).group(1)
    return dict(version=v, ships="upstream binary", trust="not inspected yet", pin_check="not inspected yet")


def aur(pkg, signed):
    t = fetch(f"https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h={pkg}")
    v = re.search(r"^pkgver=(\S+)", t, re.M).group(1)
    h = re.search(r"sha256sums=\('([0-9a-f]{64})'", t).group(1)
    return dict(version=v, ships="upstream binary (GUI tarball)", trust="sha256 pin, user-maintained",
                pin_check=match(signed, f"monero-gui-linux-x64-v{v}.tar.bz2", h))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json")
    args = ap.parse_args()

    signed = signed_hashes()
    latest = {}
    for repo in ("monero", "monero-gui"):
        r = gh(f"repos/monero-project/{repo}/releases/latest")
        latest[repo] = (r["tag_name"].lstrip("v"), r["published_at"][:10])

    rows = []

    def add(channel, fn, *a):
        try:
            rows.append(dict(channel=channel, **fn(*a)))
        except Exception as e:
            rows.append(dict(channel=channel, version="?", ships="", trust="", pin_check=f"error: {e}"))

    add("Arch Linux extra/monero", arch, "monero")
    add("Arch Linux extra/monero-gui", arch, "monero-gui")
    add("Guix monero", guix)
    add("Homebrew formula monero", homebrew_formula, signed)
    add("Homebrew cask monero-wallet", homebrew_cask, signed)
    add("Flathub org.getmonero.Monero", flathub, signed)
    add("Scoop extras/monero", scoop, signed)
    add("Docker simple-monerod", docker)
    add("nixpkgs monero-cli", nix, "monero-cli")
    add("nixpkgs monero-gui", nix, "monero-gui")
    add("FreeBSD ports monero-cli", freebsd)
    add("Chocolatey monero", chocolatey)
    add("AUR monero-gui-static-bin", aur, "monero-gui-static-bin", signed)
    try:
        for suite, v in debian():
            rows.append(dict(channel=f"Debian {suite}", version=v, ships="source (Debian package)",
                             trust="Debian archive signature over Debian's own build", pin_check="n/a"))
    except Exception as e:
        rows.append(dict(channel="Debian", version="?", ships="", trust="", pin_check=f"error: {e}"))

    cur = latest["monero"][0]
    for r in rows:
        r["current"] = "yes" if r["version"] == cur else "no"

    today = dt.date.today().isoformat()
    print(f"# Monero channel census, {today}")
    print(f"Latest release: CLI v{latest['monero'][0]} ({latest['monero'][1]}), GUI v{latest['monero-gui'][0]} ({latest['monero-gui'][1]})")
    print(f"hashes.txt: signature by binaryFate {BINARYFATE_FPR} verified, {len(signed)} entries\n")
    print("| Channel | Version | Current | Ships | What the pin trusts | Pin vs signed hashes.txt |")
    print("|---|---|---|---|---|---|")
    for r in rows:
        print(f"| {r['channel']} | {r['version']} | {r['current']} | {r['ships']} | {r['trust']} | {r['pin_check']} |")
    if args.json:
        json.dump(dict(date=today, latest=latest, rows=rows), open(args.json, "w"), indent=2)


if __name__ == "__main__":
    main()
