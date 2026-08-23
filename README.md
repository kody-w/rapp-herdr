# rapp-herdr

Run a RAPP neighborhood as a supervised Herdr workspace.

`rapp-herdr` resolves the Twin identities in a neighborhood's `members.json`
against local Twin estates, then projects the neighborhood into Herdr:

```text
Herdr workspace: Research Lab
  tab: Scout       -> Twin brainstem on :7081
  tab: Analyst     -> Twin brainstem on :7082
  tab: Skeptic     -> Twin brainstem on :7083
  tab: Synthesizer -> Twin brainstem on :7084
```

Every Twin remains its own process, workspace, RAPP identity, soul, agents,
memory, and HTTP `/chat` endpoint. The neighborhood manifest and membership
roster are read-only inputs. The controller is not enrolled as a neighbor.

## Install

Requirements:

- Python 3.11+
- Herdr 0.7.4+
- one or more full RAPP Twin workspaces

```bash
python3 -m pip install git+https://github.com/kody-w/rapp-herdr.git
```

## Start a neighborhood

Start or attach to a named Herdr session:

```bash
herdr --session twins
```

From a shell in that session, point `rapp-herdr` at the neighborhood manifest
and the local estate containing its Twin workspaces:

```bash
rapp-herdr neighborhood up ./neighborhood.json \
  --estate-root ~/.rapp/twins \
  --base-port 7081
```

By default, `members.json` is read beside `neighborhood.json` (or from the
manifest's `members_path`). Each member `rappid` is matched exactly against a
local workspace's `rappid.json`. Remote members remain remote; only locally
resolved members are started.

```bash
rapp-herdr neighborhood status ./neighborhood.json
rapp-herdr neighborhood down ./neighborhood.json
```

Use `--require-all-local` when every listed member must resolve on the current
machine. Use `--session NAME` when running the command outside a Herdr pane.
Managed Twins bind to `127.0.0.1` by default. Add
`--listen-host 0.0.0.0` only when the neighborhood intentionally exposes its
Twin endpoints to the LAN.

`brainstem.py` is the default and authoritative process entrypoint. A variant
may explicitly select an additive launcher such as
`--entrypoint utils/boot.py`; `rapp-herdr` never chooses a launcher merely
because a file exists, so retired boot tombstones cannot shadow the brainstem.

By default, runtime dependencies are installed into a private venv keyed by
the complete `requirements.txt` hash. Different neighborhoods with identical
requirements reuse that environment safely under an interpreter-scoped lock;
incompatible requirements never mutate one shared venv. `--brainstem-python`
opts into an operator-managed interpreter, which is still locked while its
requirements are checked or installed.

Shared environments intentionally accept only self-contained package
specifiers from an index. Requirements includes, constraints, editable or
local paths, direct URLs, and continuation lines fail closed because their
effective dependency content cannot be represented by the top-level file hash.

## What Herdr sees

Each Twin reports:

- agent label `rapp-twin`
- full RAPP identity as its native session ID
- canonical Twin workspace as its session path
- `Starting`, `Ready`, `Thinking`, `Blocked`, or Herdr's unseen `Done` state
- neighborhood, endpoint, and port metadata

`Ready` is reported only after the Twin's real `/health` endpoint answers.
`Thinking` spans concurrent `/chat` requests. Authentication failures and
server errors report `Blocked`; a successful later turn clears the block.

## Multi-machine neighborhoods

Run the same command on each host using that host's local estate. Every host
projects only the neighborhood members it owns. Attach from another machine
with:

```bash
herdr --remote HOST --session twins
```

`rapp-herdr` does not copy Twin state or invent cross-host membership. RAPP
identity and neighborhood manifests remain the source of truth; Herdr is the
runtime control plane.

## Run the full estate

An operator-local `rapp-herdr-estate/1.0` manifest composes device SSH aliases,
RAPP neighborhoods, Twin inventory roots, and generated estate catalogs
without replacing any of them. Start from
[`examples/estate.example.json`](examples/estate.example.json).

```bash
rapp-herdr estate plan ~/.config/rapp-herdr/estate.json
rapp-herdr estate up ~/.config/rapp-herdr/estate.json
rapp-herdr estate status ~/.config/rapp-herdr/estate.json
rapp-herdr estate down ~/.config/rapp-herdr/estate.json
```

Seed one isolated persistence-test Twin on every enabled device, then mark and
verify its local memory around a normal estate runtime restart:

```bash
rapp-herdr estate probe seed ~/.config/rapp-herdr/estate.json
rapp-herdr estate probe start ~/.config/rapp-herdr/estate.json
rapp-herdr estate probe mark ~/.config/rapp-herdr/estate.json
rapp-herdr estate probe restart ~/.config/rapp-herdr/estate.json
rapp-herdr estate probe verify ~/.config/rapp-herdr/estate.json
```

Probe workspaces use deterministic, device-specific RAPPIDs and live under the
device's first configured Twin inventory root. Existing Twins are never moved,
copied, or overwritten. The seed command also retains the previous estate
manifest as a local rollback backup before adding the managed probe
neighborhood. Probes reuse each device's installed Brainstem interpreter in
verification-only mode; they never install packages into it.

`seed` validates an existing probe's complete owned state before preserving it;
malformed JSON, incorrect identity or schema, invalid counters, and invalid
message history fail only that device's result. Managed marker, state, and mark
paths must resolve inside the probe workspace, so symlink or junction escapes
are rejected before any read or write.

`verify` treats the restarted runtime response and the state file as independent
evidence. Both must report the exact probe schema, device ID, RAPPID, survival
marker, counters, and message history; they must agree with each other, retain
the marked message, and report a boot count greater than the count captured by
`mark`.

Launch the live, read-only topology dashboard:

```bash
rapp-herdr ui ~/.config/rapp-herdr/estate.json --open
```

The dashboard refreshes from real `estate status` observations: device
reachability, Herdr sessions, runtime neighborhoods, estate workspaces,
neighborhood workers, assigned/unassigned Twins, and separately classified
non-Twin organisms. It is loopback-only, validates the browser authority, and
requires the unguessable token printed in its per-launch URL.

Use **Export backup** to download a checksummed local JSON backup of the
authoritative estate manifest. **Import backup** accepts that envelope or a
plain `rapp-herdr-estate/1.0` manifest, validates it before replacement, writes
it atomically, and retains the previous manifest beside `estate.json` as a
mode-`0600` rollback copy on POSIX. Export and import share one 2,097,152-byte
limit for the complete serialized UTF-8 JSON file, including envelope metadata
and whitespace, so every successful export is restorable by the dashboard.
Imports are serialized across dashboard instances and processes with a bounded,
crash-recoverable local lock; each rollback therefore contains the manifest
immediately preceding its import.

The estate projection has two complementary layers:

- **Runtime neighborhoods:** one Herdr workspace per RAPP neighborhood, one
  managed Twin brainstem per tab.
- **Estate catalogs:** one Herdr workspace per RAPP estate, one persistent
  `rapp-neighborhood` worker per declared neighborhood tab. A command sent to
  that pane lazily routes into the neighborhood agent or one of its factories,
  so factories are not all resident until used.

Each device runs the same local device operation. The controller sends only a
base64 JSON payload over an operator-declared SSH alias; it never builds remote
shell text from paths, prompts, or identity values. Disabled or unreachable
devices remain visible in status.

Within a neighborhood pane:

```text
/list
hello, route this work
build_factory: implement and review the requested change
/quit
```

This gives Copilot or a human one stable command surface for the full local
network estate while keeping RAPP identity, neighborhood membership, and
device ownership authoritative at their existing sources.

## Pinned Herdr source

The upstream [herdrdev/herdr](https://github.com/herdrdev/herdr) source is
pinned unmodified as the `herdr/` submodule (Apache-2.0). Clone this repository
with:

```bash
git clone --recurse-submodules https://github.com/kody-w/rapp-herdr.git
```

Normal installations use Herdr's signed release binary. The submodule provides
an auditable source pin and a development/build surface without maintaining a
private fork.

## Safety boundaries

- No RAPP manifest, membership roster, Twin kernel, or Herdr source is edited.
- Paths come only from operator-selected estate roots, never from remote
  membership metadata.
- Twin interpreters receive a package-only `rapp-herdr` bootstrap zip, never
  the controller interpreter's full `site-packages` or inherited `PYTHONPATH`.
- Duplicate identities and duplicate canonical workspaces fail before launch.
- Receipts are host/session scoped, atomically replaced, and mode `0600`.
- Re-running `up` reconciles the existing receipt instead of duplicating
  processes; changed membership, runtime requirements, or launch options fail
  closed and require an explicit `down` then `up`.
- `down` closes only a workspace whose opaque Herdr IDs and pane set still
  match the receipt.

This is an application/runtime adapter. It does not define a new RAPP wire,
identity form, neighborhood schema, or trust rule.
