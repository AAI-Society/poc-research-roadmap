# Design — `ephemeris serve`, the UDS listener and its four routes

**Date:** 2026-08-10 · **Status:** approved, ready for implementation planning ·
**Repo:** existing — [`ephemeris`](https://github.com/Task-force-for-AI-agents-in-Healthcare/ephemeris)

**This is an addendum, not a replacement.** `2026-08-10-ephemeris-design.md` already
specifies `serve` — one row of its architecture table, reading "the UDS listener and its
four routes". It never says what the four routes are. Neither does
`2026-08-10-transit-guard-claims-design.md`, which is the other half of the contract.
This document closes that gap and changes nothing else.

---

## Why this needed a decision at all

The route enumeration is an **interface contract between two components with different
owners**. `transit guard` calls it; `ephemeris` serves it. Building it means writing that
contract down, and writing it down is the part neither spec did.

The enumeration below was **derived, not invented**, and the derivation is recorded here
so that whoever owns the guard's side can object to a written thing rather than discover
it in code:

- The guard's own design shows exactly **one** interaction with `ephemeris`: submit a
  claim, block on the acknowledgement, then forward. That is one route.
- The `ephemeris` design's `proof` module is scoped to "inclusion, consistency, published
  roots" — three things an auditor reads, and nobody else. That is three routes.

One plus three is the four the specs both refer to and neither lists.

## The four routes

| route | who calls it | what it does |
| --- | --- | --- |
| `POST /claims` | `transit guard`, at step 3 of its flow | Submit one claim. **Blocks until the record is durable.** Returns the `Ack` on success and a non-2xx on every other outcome. |
| `GET /root` | an auditor or monitor | The signed tree head, rendered exactly as the CLI renders it — including the sentence saying what it does not defend against. |
| `GET /proof/inclusion` | an auditor | Prove a given record is in a tree of a given size. |
| `GET /proof/consistency` | an auditor | Prove the tree at size *m* extends into the tree at size *n*. **This is the A9 check**, served over the socket instead of the CLI. |

Only the first is on the enforcement path. The other three are read-only and serve the
audit story; a deployment that never runs an auditor still needs the first.

## Transport: a blocking UDS server, not `hyper`

The `ephemeris` design's module table lists `hyper` against `serve`, and its tech stack
names `hyper` 1, `hyper-util` and `tokio`. **This design deviates**, and the deviation is
the one substantive decision here.

`ephemeris` is blocking end to end. `QueueHandle::submit` blocks on `fsync`, which the
Phase 2 benchmark measured at ~3.4 ms on the development machine. Under `hyper` +
`tokio`, every claim would have to be routed through `spawn_blocking` to avoid stalling
the executor — a correctness hazard that is easy to get wrong, invisible when you do, and
whose symptom is latency under concurrency rather than a failure anything asserts.

The same benchmark established a ceiling of roughly **310 batches per second** on this
hardware, set by durability rather than by transport. A thread-per-connection server over
`std::os::unix::net::UnixListener` is nowhere near that constraint while serving one local
guard, and it needs no async runtime, no executor, and no new dependency at all.

So: `UnixListener`, one thread per connection, a minimal HTTP/1.1 request reader. If a
future deployment needs many concurrent auditors, that is the point to reconsider — and
the benchmark exists to say whether it is warranted.

`serve` sits behind a `serve` cargo feature, so the default build and the default test
suite are unchanged.

## The properties that must hold

**Fail-closed across the socket.** `POST /claims` returns 200 with an `Ack` body **only**
after `submit` returns `Ok`. Refusal, a dead commit loop, a malformed request, an
oversized body — every one of them is a non-2xx with no `Ack`. A guard receiving a non-2xx
must not forward, and the route must give it no way to mistake one outcome for the other.
This is C7.1.3 crossing a socket, and it is the same guarantee `Ack`'s single construction
site enforces in-process: the listener *relays* an `Ack`, it never builds one.

**No panics on anything read from the socket.** This code parses HTTP from a caller it did
not write. Truncated requests, absent or absurd `Content-Length`, bodies larger than any
plausible claim, invalid UTF-8, unknown methods and paths — all return errors. The crate's
existing rule applies unchanged: no `unwrap`, `expect`, slice indexing, or unchecked
conversion on anything off the wire.

**The socket's permissions are the access control, and that is a stated limitation.** The
`ephemeris` design already says it: "anything that can write to the socket can insert
records." The socket is created mode `0600`. A stale socket file at the path is removed
before bind, rather than failing with an opaque `EADDRINUSE`. There is no authentication
beyond filesystem permissions, and the README must say so rather than implying the socket
is a security boundary.

**One renderer, not two.** `GET /root` serves the output of the same `render()` the CLI
prints. A second formatter would eventually drift, and the thing it would drift on is the
sentence declaring what the root does not defend against — the one piece of text this
project least wants quietly reworded.

**Proofs served must verify with the same verifier.** The inclusion and consistency proofs
returned over the socket are produced by the same `tree` functions the CLI and the tests
use. A proof that verifies in-process and not over the wire, or vice versa, means a
serialization bug in exactly the place a serialization bug is least detectable.

## Failure modes

**A slow or hostile client holds a connection open.** Thread-per-connection means one
thread per open connection, and a client that connects and never sends is a thread parked
forever. Read timeouts bound it. This is a local socket with filesystem permissions in
front of it, so the threat is a buggy guard rather than an adversary, but an unbounded
thread count is still an outage.

**The commit queue dies while the listener lives.** `QueueHandle::submit` already returns
`NotDurable` rather than blocking forever when its loop is gone. The route must surface
that as a non-2xx rather than a 200 with an error-shaped body.

**A claim larger than any plausible record.** Bodies are bounded before allocation, in the
same shape as `store`'s `MAX_RECORD` check, so a hostile `Content-Length` cannot become a
memory exhaustion.

## Testing

Everything offline, over a real socket in a temporary directory:

- a claim round-trips and is present after reopening the store — durability asserted from
  disk, not from the response;
- a refused claim yields a non-2xx and **no** `Ack`, from a queue whose store was broken
  before the request;
- malformed input — truncated request, bad `Content-Length`, oversized body, unknown
  method, unknown path — produces errors rather than panics;
- `GET /root` output contains the undefended-property sentence, and is byte-identical to
  what the CLI prints for the same log;
- a proof fetched over the socket verifies with the same verifier the CLI uses, and a
  proof fetched against a rewritten log fails — the A9 property, end to end over the
  transport.

The last one matters most: it is the whole point of the component, checked through the
interface a real auditor would use.

## What this does not do

**No authentication.** Filesystem permissions only, stated plainly rather than implied
away.

**No cross-host logging.** A Unix domain socket means writer and log share a machine. The
`ephemeris` design already records this as a limitation the fleet case will eventually
force; nothing here changes it.

**No change to what a record contains.** `path_summary_hash` remains `Option` and a claim
omitting it is accepted and recorded as `null` — the guard spec's fork resolved to
shipping the field unfilled, and `ephemeris` already implements exactly that. Verified: a
claim without the field is accepted today and the record carries `null`.

## Build order

1. The listener, the socket's lifecycle and permissions, and a minimal request reader —
   with the malformed-input tests, because that is the surface an attacker reaches first.
2. `POST /claims`, with the fail-closed tests.
3. The three read routes, sharing the CLI's renderer and the crate's verifiers.
4. CI, README, and the statement that the socket is not an authentication boundary.

Step 1 is useful alone: a listener that refuses everything safely is a better starting
point than one that accepts a claim it cannot bound.
