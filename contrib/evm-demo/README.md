# EVM-on-Stacks — end-to-end demo

A narrated, terminal walkthrough of the experimental EVM support: real
Solidity-style contracts running as native Stacks transactions on a **live
regtest Nakamoto network** (bitcoind + 5 signers + a miner), booted to
Epoch 3.3.

The demo is the `evm_demo` integration test in
`stacks-node/src/tests/signer/v0/evm_txs.rs`. It reuses the project's own
signer test harness, so what you see is the full consensus path — real block
proposals, real signer signatures, real block production — not a simulation.

## What it shows

1. **Boot** a regtest Nakamoto chain to Epoch 3.3 (where the EVM payloads
   activate). One Stacks key controls both the Stacks and the EVM address.
2. **`EvmPublish`** — deploy a payable "Vault" contract.
3. **`EvmContractCall`** with `msg.value` — store a value and send 5 STX;
   the STX moves through the real account ledger to the contract's own Stacks
   principal, and the EVM log surfaces on the standard Stacks event feed.
4. **`EvmContractCall`** read path — read the stored value back in a later
   transaction (state persisted in the MARF).
5. **Deploy a Clarity contract**, then use the **`clarity-read` precompile**
   so an EVM contract reads a value straight out of that Clarity contract
   (EVM → Clarity).
6. **`(evm-call? ...)`** — the reverse bridge: a Clarity contract drives the
   EVM, writing storage and attaching `msg.value` drawn from its *own* STX
   balance (Clarity → EVM). `msg.sender` is the calling contract, never
   `tx-sender`, so a callee can't spend a user's funds through this path.
7. **Read back** the EVM slot that has now been written by both VMs.
8. **Revert** — a failing call is still mined (nonce consumed, fee paid) but
   changes no state.

## Run it

```sh
# from the repository root
podman build -t evm-demo -f contrib/evm-demo/Dockerfile .

# press Enter to advance each step; capture stdout so the terminal shows
# only the walkthrough panels while full logs land in node.log.
# NOTE: -i WITHOUT -t (see below).
podman run --rm -i evm-demo 1>node.log
```

The walkthrough panels are written to **stderr** and the node/signer/bitcoind
logs to **stdout** (in a test build the stacks logger owns stdout). Redirecting
stdout to a file therefore leaves a clean panel view on the terminal while
preserving every log line in `node.log` for debugging. Stepping still works
under plain `-i`: stdin stays connected, so pressing Enter advances each step;
with no stdin at all the demo auto-advances.

**Use `-i`, not `-it`, when capturing.** The `-t` flag allocates a pseudo-TTY
that merges stdout and stderr onto one stream, which defeats the `1>node.log`
split (everything, panels included, ends up together). If you don't care about
separating them, `podman run --rm -it evm-demo` shows panels and logs
interleaved on one screen.

## Requirements & notes

- **Build is heavy.** The image compiles Bitcoin Core from source and the
  whole Rust workspace (stackslib + `revm` + the node test harness). Expect a
  long first build (tens of minutes) and roughly **16 GB RAM**, per the
  project's build guidance.
- **bitcoind is pinned and built from source** (Bitcoin Core `v28.1`, verified
  against a `sha512` checksum in the Dockerfile); the harness launches it
  automatically.
- **Runs unprivileged.** Root is used only for the initial system setup
  (building/installing bitcoind and creating a `dev` user); the image drops to
  that unprivileged user with `USER` before the source is copied, so the build
  and the demo itself never run as root. Cargo builds into a `dev`-owned
  `CARGO_TARGET_DIR=/target`.
- The build context is the **repository root** (note the `-f` flag and the
  trailing `.`), so a `.dockerignore` lives at the repo root to keep the
  context small. Everything else for the demo lives here in
  `contrib/evm-demo/`.
- The EVM bytecode used is minimal, **hand-assembled** bytecode (the same
  fixtures the unit tests exercise). The "equivalent Solidity" shown in the
  panels describes what that bytecode does; it is not compiled from it.

## Run the same flow without a container

```sh
BITCOIND_TEST=1 cargo test -p stacks-node evm_demo -- --ignored --nocapture --test-threads=1
```

(Requires `bitcoind` on your `PATH`.)
