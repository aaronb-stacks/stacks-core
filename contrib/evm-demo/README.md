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

# three-pane tmux demo
podman run --rm -it evm-demo
```

This opens a tmux window with three panes:

```
+---------------------------+---------------------------+
|  demo walkthrough         |  node / signer / bitcoind |
|  (stderr)                 |  logs (stdout)            |
|  <- press Enter here      |                           |
+---------------------------+---------------------------+
|  RPC shell: curl + jq against the running node        |
+-------------------------------------------------------+
```

**Focus the top-left pane and press Enter to advance each step.** Switch panes
with `Ctrl-b` then an arrow key (mouse clicks work too). While the demo is
paused between steps, use the bottom pane to query the live node and show what
just happened on-chain.

The walkthrough is written to **stderr** and the logs to **stdout** (in a test
build the stacks logger owns stdout); `tmux-demo.sh` redirects stdout to a log
file inside the container, which is why `-it` is fine here even though a
pseudo-TTY merges the container's own streams.

### The RPC pane

The running demo publishes its endpoint and every address it creates into
`/tmp/evm-demo/rpc.env`, which the helper commands re-read on each call, so
addresses become available as soon as the demo reaches the step that creates
them. Type `help` in that pane for the list. The most useful ones:

| command | shows |
|---|---|
| `addrs` | every address the demo has published so far |
| `chain` | chain tip / epoch (`GET /v2/info`) |
| `vault` | the EVM contract's **STX balance** — the "1 wei == 1 uSTX" proof |
| `sender` | the demo sender's balance + nonce |
| `caller` | the Clarity contract that drives the EVM (its balance funds `msg.value`) |
| `oracle` | read the Clarity oracle the EVM reads through the precompile |
| `acct <principal>` / `tx <txid>` | any account / transaction |

Good moments to run them, while paused:

- after **STEP 1** → `addrs`, `vault` (contract exists, balance still 0)
- after **STEP 2** → `vault`, `sender` (5 STX moved into the EVM contract)
- after **STEP 4** → `oracle` (the Clarity value the EVM is about to read)
- after **STEP 6** → `caller`, `vault` (Clarity paid the EVM from its own balance)

### Single-stream alternative

For a plain, non-tmux run (no RPC pane):

```sh
podman run --rm -i --entrypoint bash evm-demo /src/contrib/evm-demo/run-demo.sh 1>node.log
```

Here use `-i` **without** `-t`: a pseudo-TTY would merge stdout and stderr and
defeat the `1>node.log` split.

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
