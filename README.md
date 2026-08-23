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
