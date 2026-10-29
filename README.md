# monero-channel-integrity

Most people do not install Monero from getmonero.org and check binaryFate's signature by hand.
They install it from Homebrew, Flathub, Arch, Scoop, nixpkgs, Debian, Docker images and similar
channels. This repository measures, per channel, two things:

1. **What the channel's pin trusts.** Does the packaging process verify a Monero signature (signed
   `hashes.txt` or a signed git tag), or does it pin whatever the download server or release page
   served when a bot refreshed it?
2. **Whether the pin matches the release.** For channels that ship release artefacts, the pinned
   SHA-256 is compared with the entry in the current `hashes.txt`, after the signature on that file
   is verified against binaryFate's key from `utils/gpg_keys` in the Monero repository.

It also records which version each channel ships, so lag behind the current release is visible.

## Run

```
py channel_census.py --json census.json
```

Python 3 standard library and `gpg` on PATH. Set `GITHUB_TOKEN` to avoid the unauthenticated
GitHub API limit. The script refuses to report anything if the `hashes.txt` signature does not
verify (`VALIDSIG 81AC591FE9C4B65C5806AFC3F0AF4D462A0BDF92`).

## First census, 2026-10-29

Latest release: CLI and GUI v0.18.5.4 (2026-10-17). Full output: [census-2026-10-29.md](census-2026-10-29.md),
machine-readable: [census-2026-10-29.json](census-2026-10-29.json).

- Every release-artefact pin that could be checked (Homebrew formula and cask, Flathub, Scoop) matches
  the signed `hashes.txt`. The Docker image `sethforprivacy/simple-monerod` pins the same commit as
  the signed `v0.18.5.4` tag.
- Only Arch Linux verifies a Monero signature as part of packaging (`?signed#tag=` with
  `validpgpkeys`). Homebrew's version bumps are made by BrewTestBot, Flathub's manifest is refreshed
  by flatpak-external-data-checker, and Scoop's autoupdate scrapes the hash from the GitHub release
  page. None of these steps checks the signed list.
- 5 channels ship an older version: nixpkgs (CLI 0.18.5.1, GUI 0.18.5.2), FreeBSD ports (0.18.4.3),
  Chocolatey (0.18.3.4), AUR `monero-gui-static-bin` (0.18.5.0) and Debian (unstable 0.18.5.3;
  stable trixie 0.18.4.0; bookworm 0.18.0.0; bullseye still lists 0.17.2.0, which predates the
  2022 network upgrade).

This is a first pass over 13 channel entries plus Debian suites. The scope, method and next steps
are in [PROPOSAL.md](PROPOSAL.md).

## Scope and conduct

The census reads public packaging metadata only. It downloads no binaries and tests no one's
infrastructure. If a pin ever fails to match the signed list, the finding goes privately to the
channel maintainers and to Monero's vulnerability response process before anything is published.

## License

MIT
