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
rapp-herdr estate audit ~/.config/rapp-herdr/estate.json
rapp-herdr estate down ~/.config/rapp-herdr/estate.json
```

Launch the live, read-only topology dashboard:

```bash
rapp-herdr ui ~/.config/rapp-herdr/estate.json --open
```

The dashboard refreshes from real `estate status` observations: device
reachability, Herdr sessions, runtime neighborhoods, estate workspaces,
neighborhood workers, assigned/unassigned Twins, and separately classified
non-Twin organisms. Its global index can filter devices, neighborhoods, Twins,
assets, services, and jobs, then group them by type, device, compliance, or
status. Follow Active automatically expands and scrolls to the currently
working or blocked worker. It is loopback-only, validates the browser
authority, and requires the unguessable token printed in its per-launch URL.

Machine audit is read-only and allowlist-bounded. It inventories declared
RAPP/1 candidates without claiming conformance, legacy RAPP, non-RAPP AI
workspaces, malformed/stale records, listeners, scheduled jobs, egg metadata,
and live-versus-persisted Herdr state. Secret-bearing paths and symlink escapes
are omitted; traversal has global depth/path/asset limits.

The UI can export a checksummed estate backup and import it only after schema
validation, checksum verification, operator confirmation, and creation of a
timestamped rollback copy.

Persistence probes provide an opt-in survival test across every enabled device:

```bash
rapp-herdr estate probe seed ~/.config/rapp-herdr/estate.json
rapp-herdr estate probe start ~/.config/rapp-herdr/estate.json
rapp-herdr estate probe mark ~/.config/rapp-herdr/estate.json
rapp-herdr estate probe restart ~/.config/rapp-herdr/estate.json
rapp-herdr estate probe verify ~/.config/rapp-herdr/estate.json
```

Each enabled device must declare a `probe_target`: one real loopback Twin on
that same device. Probe `/chat` turns are relayed to that Twin and succeed only
when it replies; storing the marker alone is a failure. Relay state preserves
the target session and bounded receipts across probe restarts. A successful
reply is the authoritative presence signal: the target is live, online, and
ready to chat, regardless of its prior Herdr attention state.

## Create a buddy anywhere in the herd

Native buddy mode creates a bounded rapplication Twin on any enabled estate
device:

```bash
rapp-herdr estate buddy create ~/.config/rapp-herdr/estate.json \
  --device rappter-two \
  --name "Research Buddy" \
  --role "Research questions and cite evidence." \
  --ui auto
```

`--ui chat` uses the canonical Brainstem chat. `--ui rapplication` generates a
static role front end. `--ui auto` chooses a custom front end for visual,
dashboard, workflow, studio, tracker, portal, monitor, builder, or report roles;
other roles use chat. Every custom UI includes **Use default chat**, so the
canonical `/chat` experience is always recoverable.

Creation mints a keyless RAPP/1 identity under the estate's explicit
`buddy_owner`, writes an owned Twin workspace and one-member neighborhood,
registers and launches it through Herdr, then marks it online only after an
identity-nonce health check and a real `/chat` response ending in `READY`.
Failure rolls back only resources carrying the matching buddy ownership marker.

The central roster and chat RPCs keep clients from reimplementing device
routing:

```bash
rapp-herdr estate buddy list ~/.config/rapp-herdr/estate.json
rapp-herdr estate buddy chat ~/.config/rapp-herdr/estate.json \
  --buddy BUDDY_ID --message "Are you ready?"
```

Embedded clients may add `--stdin` to `buddy create` or `buddy chat` and send
the corresponding JSON object over standard input, keeping roles and messages
out of process arguments.

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
