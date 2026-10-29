# Monero Channel Integrity

Research proposal to the MAGIC Monero Fund. Applicant: Emil Huseynov (Baku, Azerbaijan).
Requested: USD 6,000 over 12 weeks.

## 1. Research question

Monero's integrity story for users rests on one signed file: `hashes.txt`, signed by binaryFate,
plus signed git tags for source. The official guides tell users to verify that signature before
running anything. In practice most users never touch GPG. They type `brew install monero`,
`apt install monero`, `flatpak install org.getmonero.Monero`, `scoop install monero` or pull a Docker
image, and whatever the packager did becomes their verification.

So the question this project answers is:

> For each channel through which people actually obtain Monero, what does the channel's pin trust,
> does that pin match what Monero's maintainers signed, and how far behind the current release do
> its users sit?

This matters for two concrete reasons.

**A download-server compromise is not hypothetical for Monero.** On 18 November 2019 the CLI
binaries served from getmonero.org were replaced with builds that sent the wallet seed to an
attacker; it was caught because a user checked the hash and it did not match. Today Homebrew and
Flathub update their pins through bots that download the new file from getmonero.org and propose
whatever hash it has (BrewTestBot, flatpak-external-data-checker); a reviewer then merges the change
without any signature check. If the same compromise landed at release time, both would most likely
pin the attacker's file and ship it as a normal update. Scoop takes its
hash from the GitHub release page, a second origin that would catch a website-only compromise, but
that text is not signed either. Nothing in these pipelines compares the pin with the signed list.

**Lag strands users on old code, and the next network upgrade will make it worse.** Ubuntu 22.04
LTS, still a supported release, ships `monero` 0.17.2.0 through apt (universe), a version that cannot follow
the network since the 2022 v0.18 upgrade. Ubuntu 24.04 LTS ships 0.18.3.1. nixpkgs unstable ships
CLI 0.18.5.1 and so misses the 0.18.5.3 "highly recommended" release and the 0.18.5.4 fix to DNSSEC
validation for checkpoints, blocklists and update checks. The FCMP++ upgrade will require every node
and wallet to update; channels that lag by months will leave their users on the wrong side of it.

## 2. Existing work

- **Monero's own verification guidance** (getmonero.org user guides, monero-docs "Verifying Monero
  binaries", community scripts such as setuidroot/monero-verify) addresses users who download
  directly. It says nothing about packagers.
- **Reproducible builds.** Monero builds releases with Guix (monero-project/monero#8929, "Bootstrappable
  Builds"), so independent builders can reproduce them. That makes the official artefacts checkable; it does
  not tell anyone whether Homebrew or Flathub shipped those artefacts.
- **Repology** tracks package versions across distributions (36 repositories for `monero-cli`, 24 for
  `monero-gui`; 30 of 40 `monero-cli` entries flagged outdated on 2026-10-29). It measures version
  only. It does not look at what a pin trusts, does not verify anything against the signed list, and
  does not map lag to the security content of the releases users are missing.
- **Supply-chain integrity research** in general: The Update Framework (Samuel et al., CCS 2010) and
  Diplomat (Kuppusamy et al., NSDI 2016), in-toto (Torres-Arias et al., USENIX Security 2019),
  reproducible builds (Lamb and Zacchiroli, IEEE Software 2022), and measurements of technical lag in
  package ecosystems (Zerouali et al., 2018-2019). These give the vocabulary (trust anchor, key
  compromise, freeze attacks, lag) but none of them looks at Monero's distribution channels.

I have not found any measurement of how Monero's third-party channels verify releases.

## 3. Preliminary work (done before applying)

I wrote `channel_census.py` (public in this repository). It verifies the signature on the current
`hashes.txt` against binaryFate's key from `utils/gpg_keys`, then reads the live packaging metadata
for 13 channel entries plus all Debian suites, records the version and what the pin trusts, and
compares every pinned release artefact with the signed list. Result on 2026-10-29 (latest release
v0.18.5.4, 2026-10-17):

| Channel | Version | What the pin trusts | Pin vs signed list |
|---|---|---|---|
| Arch Linux extra (monero, monero-gui) | 0.18.5.4 | makepkg verifies the git tag signature (`validpgpkeys`) | n/a, signature checked |
| Guix | 0.18.5.4 | hash of the git tag, no signature check | n/a |
| Homebrew formula | 0.18.5.4 | sha256 pin, bumped by BrewTestBot | match |
| Homebrew cask monero-wallet | 0.18.5.4 | sha256 pin, bot-bumped | match |
| Flathub org.getmonero.Monero | 0.18.5.4 | sha256 pin, refreshed by flatpak-external-data-checker | match |
| Scoop extras/monero | 0.18.5.4 | hash scraped from the GitHub release page | match |
| Docker sethforprivacy/simple-monerod | 0.18.5.4 | commit hash checked at build; tag signature not checked | commit matches signed tag |
| nixpkgs monero-cli / monero-gui | 0.18.5.1 / 0.18.5.2 | hash of the git tag, no signature check | n/a |
| FreeBSD ports monero-cli | 0.18.4.3 | distinfo sha256 of the GitHub tarball | n/a |
| Chocolatey monero | 0.18.3.4 | not inspected yet | - |
| AUR monero-gui-static-bin | 0.18.5.0 | sha256 pin, user-maintained | older than current list |
| Debian unstable / trixie / bookworm / bullseye | 0.18.5.3 / 0.18.4.0 / 0.18.0.0 / 0.17.2.0 | Debian's own signed build | n/a |

Three things stand out already. Every pin that could be checked matches, which is good news and a
baseline. Only one channel, Arch, checks a Monero signature in its packaging process; the
others rely on the download server or the release page being honest at the moment a bot looks.
And the lag is large on exactly the channels non-technical users reach first (Ubuntu and Debian
LTS releases, Chocolatey on Windows).

## 4. Research plan

**Month 1: full census.** Extend the census from 13 entries to every channel Repology lists for
`monero-cli` and `monero-gui` (66 entries across Alpine, Gentoo GURU, openSUSE, Ubuntu, Devuan,
Kali, Raspbian, Manjaro and others), plus the node-in-a-box platforms many node
operators use (Umbrel, Start9) and the most-pulled Monero Docker images. For each entry, record: the
artefact shipped (upstream binary or own build), the trust anchor of the pin (signed list, signed
tag, hash of a git ref, bot download, scraped page), who or what performs updates, and whether the
pin matches the signed release. Inspect Chocolatey's install script and checksum source.

**Month 2: history since v0.18.0.0.** Reconstruct every pin each channel has shipped since July 2022
from its packaging history (homebrew-core, homebrew-cask, Flathub, Scoop Extras, nixpkgs, Arch
packaging, AUR, FreeBSD ports, Docker repositories, Debian and Ubuntu snapshot archives). Verify
each historical release-artefact pin against the signed `hashes.txt` of that release, recovered from
the monero-site repository history (108 revisions of `downloads/hashes.txt` since 2016). Measure time-to-ship per release and per channel, and for each
channel list the releases its users were missing at each point, weighted by what those releases
fixed (for example the 0.18.5.1 txpool use-after-free fix, the 0.18.4.3 spy-node protections, the
0.18.5.4 DNSSEC fix). Output: a dataset and a short paper-style write-up.

**Month 3: a monitor, and fixes upstream.** Turn the census into a GitHub Actions job that runs on
every Monero release and daily: verify the `hashes.txt` signature, check every channel's pin and
version, publish a status page, and open an issue (or notify the channel maintainer) on a mismatch
or on lag beyond a threshold. In parallel, send concrete changes to channels where verification can
be added within their own tooling, for example pointing Scoop's autoupdate hash source at the signed
`hashes.txt` instead of the release page, or adding a signature check to bot-driven bump workflows,
and send update requests to lagging channels.

Any pin that does not match the signed list is treated as a possible compromise: reported privately
to the channel maintainers and through Monero's Vulnerability Response Process, and published only
after it is resolved, in line with the Fund's 90-day rule.

## 5. Integration with Monero

- **Downloads page and docs.** Propose to monero-site and monero-docs a "third-party packages" table
  generated from the monitor: which channels verify signatures, which are current, which to avoid.
  Today getmonero.org gives users no guidance on packaged installs.
- **Release process.** Share the time-to-ship data with the release maintainers so a release
  announcement can reach the packagers that lag most, and so the FCMP++ upgrade can be planned
  knowing which channels will need a push.
- **Ownership.** The monitor is MIT-licensed and needs no secrets beyond a GitHub token. I will run
  it for at least a year after the grant and am happy to move it under the monero-project
  organisation if the maintainers want it.

Discussion happens in public GitHub issues on the relevant repositories, so the work stays
reviewable by anyone.

## 6. Budget and payment

About 150 hours over 12 weeks (roughly 12 hours a week next to my day job), at USD 40 per hour:
**USD 6,000**. No equipment is needed; the census and monitor run on GitHub Actions.

| Payment | Milestone | Amount |
|---|---|---|
| End of month 1 | Full census of all channels published, Chocolatey and Docker images inspected | USD 2,000 |
| End of month 2 | Historical dataset and write-up published | USD 2,000 |
| End of month 3 | Monitor live with status page, upstream changes and update requests sent, final report | USD 2,000 |

Payment by USD bank wire, or in XMR or BTC if that is simpler for the Fund.

## 7. About me

I am a security researcher and backend developer in Baku (backend developer at Baku State
University; M.Sc. in Information Security at Azerbaijan Technical University). In audit competitions
I have six paid findings (four High, one Medium, one Insight) on Immunefi and HackenProof, including
a High on Firelight that was upheld after my rebuttal, and further Highs confirmed real on Cantina
and HackerOne. I also report vulnerabilities in open-source tools through GitHub security advisories.

This year I wrote about 40 empirical security measurement papers, each with a replication package;
about 10 are under peer review. Several ask this proposal's question for other ecosystems: whether
npm provenance attestations can be reconstructed, whether Sigstore signatures can actually be
verified, whether PyPI attestations bind to their source, and whether pinned container tags get
rebuilt. Monero is the ecosystem where a wrong answer costs users their funds directly.

- GitHub: https://github.com/emilhuseyn
- Example replication package: https://github.com/emilhuseyn/sca-reachability-verdict-audit
- Firelight finding (public): https://github.com/immunefi-team/Past-Audit-Competitions/blob/main/firelight-sep.2026-or-audit-competition/89428-sc-high-inclusive-period-start-snapshot-in-firelightvault-lets-any-liquidity-provider-cap-inci.md
