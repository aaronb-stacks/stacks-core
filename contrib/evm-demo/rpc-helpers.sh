#!/usr/bin/env bash
#
# Helper shell functions for the EVM-on-Stacks demo's RPC pane.
#
# The running demo publishes its endpoint and the addresses it creates into
# $DEMO_ENV (KEY=value lines) as it goes; every helper re-reads that file, so
# addresses discovered later in the demo (the vault, the Clarity contracts)
# become available as soon as the demo reaches that step.

DEMO_ENV="${DEMO_ENV:-/tmp/evm-demo/rpc.env}"
DEMO_HELPERS="${BASH_SOURCE[0]}"
NODE_LOG="${NODE_LOG:-/tmp/evm-demo/node.log}"
BLOCKS_FILE="${BLOCKS_FILE:-/tmp/evm-demo/blocks.json}"

# Load the demo-published variables (NODE, SENDER, VAULT, ...) into the
# current shell.
_demo_load() {
    if [ -f "$DEMO_ENV" ]; then
        # shellcheck disable=SC1090
        set -a; . "$DEMO_ENV"; set +a
    fi
    if [ -z "${NODE:-}" ]; then
        echo "the demo has not published its RPC endpoint yet -- wait for STEP 0" >&2
        return 1
    fi
}

# Show every address the demo has published so far.
addrs() {
    _demo_load || return 1
    echo "NODE   = $NODE"
    echo "SENDER = ${SENDER:-<pending>}"
    echo "VAULT      (EVM contract, as a Stacks principal) = ${VAULT:-<pending>}"
    echo "VAULT_EVM  (its 20-byte EVM address)             = ${VAULT_EVM:-<pending>}"
    echo "ORACLE     (Clarity contract read by the EVM)    = ${ORACLE:-<pending>}"
    echo "CALLER     (Clarity contract driving the EVM)    = ${CALLER:-<pending>}"
}

# Chain tip / epoch summary.
chain() {
    _demo_load || return 1
    curl -s "$NODE/v2/info" | jq '{
        stacks_tip_height, burn_block_height,
        stacks_tip, network_id, server_version
    }'
}

# Decimal uSTX balance of a principal (the RPC returns it as hex).
_ustx() {
    curl -s "$NODE/v2/accounts/$1?proof=0" \
        | jq -r '.balance | ltrimstr("0x") | ascii_downcase | explode
                 | map(if . >= 97 then . - 87 else . - 48 end)
                 | reduce .[] as $d (0; . * 16 + $d)'
}

# One-shot balance table for every account in the demo. Run it before and
# after a value-moving step to see the ledger change.
balances() {
    _demo_load || return 1
    printf '%-18s %-46s %14s\n' WHO PRINCIPAL uSTX
    printf '%-18s %-46s %14s\n' "sender" "$SENDER" "$(_ustx "$SENDER")"
    if [ -n "${VAULT:-}" ]; then
        printf '%-18s %-46s %14s\n' "vault (EVM)" "$VAULT" "$(_ustx "$VAULT")"
    fi
    if [ -n "${CALLER:-}" ]; then
        printf '%-18s %-46s %14s\n' "caller (Clarity)" "$CALLER" "$(_ustx "$CALLER")"
    fi
}

# Print a contract's source as stored on chain: `src` (the evm-caller) or
# `src <addr>.<name>`. Handy for showing real `(evm-call? ...)` Clarity on
# chain, not in a slide.
src() {
    _demo_load || return 1
    local id="${1:-${CALLER:-}}"
    if [ -z "$id" ]; then
        echo "usage: src <addr>.<contract-name>" >&2
        return 1
    fi
    local addr="${id%%.*}" name="${id##*.}"
    curl -s "$NODE/v2/contracts/source/$addr/$name?proof=0" | jq -r '.source'
}

# Balance and nonce for any principal: `acct SP...` or `acct SP....contract`
acct() {
    _demo_load || return 1
    local who="$1"
    if [ -z "$who" ]; then
        echo "usage: acct <principal>" >&2
        return 1
    fi
    curl -s "$NODE/v2/accounts/$who?proof=0" \
        | jq '{balance_hex: .balance, nonce, locked}
              | .balance_uSTX = (.balance_hex | ltrimstr("0x") | ascii_downcase
                                 | explode | map(if . >= 97 then . - 87 else . - 48 end)
                                 | reduce .[] as $d (0; . * 16 + $d))'
}

# The EVM contract's STX balance -- this is the "wei == uSTX" proof.
vault() {
    _demo_load || return 1
    if [ -z "${VAULT:-}" ]; then
        echo "vault not deployed yet -- wait for STEP 1" >&2
        return 1
    fi
    echo "vault principal: $VAULT   (EVM address ${VAULT_EVM:-?})"
    acct "$VAULT"
}

# The Clarity contract that drives the EVM (its balance funds msg.value).
caller() {
    _demo_load || return 1
    if [ -z "${CALLER:-}" ]; then
        echo "caller contract not deployed yet -- wait for STEP 6" >&2
        return 1
    fi
    acct "$CALLER"
}

# The demo's sending account.
sender() {
    _demo_load || return 1
    acct "$SENDER"
}

# Call the Clarity oracle read-only, the same function the EVM reads.
oracle() {
    _demo_load || return 1
    if [ -z "${ORACLE:-}" ]; then
        echo "oracle not deployed yet -- wait for STEP 4" >&2
        return 1
    fi
    local addr="${ORACLE%%.*}" name="${ORACLE##*.}"
    curl -s -X POST "$NODE/v2/contracts/call-read/$addr/$name/get-answer" \
        -H 'content-type: application/json' \
        -d "{\"sender\":\"$SENDER\",\"arguments\":[]}" | jq
}

# Fetch a transaction by txid (hex, with or without 0x).
tx() {
    _demo_load || return 1
    local id="${1#0x}"
    if [ -z "$id" ]; then
        echo "usage: tx <txid>" >&2
        return 1
    fi
    curl -s "$NODE/v2/transactions/$id" | jq
}

# Live balance watch, handy while stepping through the value-transfer steps.
# Ctrl-c to stop.
watch-balances() {
    _demo_load || return 1
    while true; do
        clear
        echo "sender:"; sender
        echo "vault:";  vault 2>/dev/null || echo "  (not deployed yet)"
        sleep 2
    done
}

# ---------------------------------------------------------------------------
# Block / event / log inspection
#
# The demo snapshots the event observer (every block, transaction and event
# the node emitted) into $BLOCKS_FILE each time it pauses, so these read real
# observer data rather than scraping logs. `evmlog` and `logs` grep the node's
# own log for comparison.
# ---------------------------------------------------------------------------

_blocks_ready() {
    if [ ! -s "$BLOCKS_FILE" ]; then
        echo "no block snapshot yet ($BLOCKS_FILE) -- reach the next pause first" >&2
        return 1
    fi
}

# The most recent transactions the node mined: status, txid, and result.
txs() {
    _blocks_ready || return 1
    local n="${1:-12}"
    jq -r --argjson n "$n" '
        [ .[] | .transactions[]? | select(.txid != "0x00") ]
        | .[-$n:] | .[]
        | "\(.status | (. + "            ")[0:18]) \(.txid[0:22])  result=\((.raw_result // "")[0:26])"
    ' "$BLOCKS_FILE"
}

# Every event the node emitted, newest last.
events() {
    _blocks_ready || return 1
    local n="${1:-15}"
    jq -r --argjson n "$n" '
        [ .[] | .events[]? ] | .[-$n:] | .[]
        | "\((.type // "?") | (. + "                 ")[0:18]) txid=\(.txid[0:20])  \(.contract_event.topic // "")"
    ' "$BLOCKS_FILE"
}

# Just the EVM logs, with the Solidity topic decoded out of the Clarity buff.
# The buff payload is [n_topics][topic * n][data]; the Clarity serialization
# prefixes it with 0x02 and a 4-byte length.
evm-events() {
    _blocks_ready || return 1
    jq -r '
        [ .[] | .events[]? | select(.contract_event.topic == "evm-log") ] | .[]
        | (.contract_event.raw_value | ltrimstr("0x")) as $v
        | ($v[10:12] | ascii_downcase | explode
           | map(if . >= 97 then . - 87 else . - 48 end)
           | reduce .[] as $d (0; . * 16 + $d)) as $ntopics
        | "txid=\(.txid[0:20])  contract=\(.contract_event.contract_identifier)
    topics=\($ntopics)  topic0=0x\($v[12:76])
    data=0x\($v[76:140])"
    ' "$BLOCKS_FILE"
}

# Per-block summary: height, tx count, event count.
blocks() {
    _blocks_ready || return 1
    local n="${1:-10}"
    printf '%-8s %-9s %-8s %s\n' HEIGHT TXS EVENTS BLOCK_ID
    jq -r --argjson n "$n" '
        .[-$n:] | .[]
        | [ (.block_height // 0 | tostring),
            ((.transactions // []) | length | tostring),
            ((.events // []) | length | tostring),
            ((.index_block_hash // .block_hash // "?")[0:20]) ]
        | @tsv
    ' "$BLOCKS_FILE" | awk -F'\t' '{printf "%-8s %-9s %-8s %s\n", $1, $2, $3, $4}'
}

# ---------------------------------------------------------------------------
# Raw node log lines -- the node's actual output, unparsed, with the match
# highlighted. These are the most convincing thing to show: not a summary the
# demo produced, but what the node itself wrote while doing the work.
# ---------------------------------------------------------------------------

_rawlog() {
    local pat="$1" n="${2:-10}"
    if [ ! -s "$NODE_LOG" ]; then
        echo "no node log yet at $NODE_LOG" >&2
        return 1
    fi
    grep -a -E --color=always "$pat" "$NODE_LOG" | tail -n "$n"
}

# The EVM interpreter running, as the node logs it: payload type, gas used,
# whether it succeeded, and the created contract address.
#
# Expect the same tx more than once: the miner executes it, then every signer
# re-executes it while validating the block proposal. That repetition IS the
# consensus -- worth pointing at.
evmlog() { _rawlog "EVM transaction processed" "${1:-6}"; }

# Signers accepting the block that carried the EVM transaction.
signerlog() {
    _rawlog "Received block acceptance|Received a new block event|Got block pushed message" "${1:-8}"
}

# Blocks moving through the node.
blocklog() {
    _rawlog "Handle incoming Nakamoto block|Append block|Advanced to new tip|Block accepted" "${1:-8}"
}

# HTTP the node served -- including the demo's own POST /v2/transactions and
# the /v2/accounts calls you make from this pane.
rpclog() { _rawlog "Handled StacksHTTPRequest" "${1:-10}"; }

# Grep the node log for anything: `logs "Append block"`, `logs evm-caller` ...
logs() {
    if [ -z "${1:-}" ]; then
        echo "usage: logs <pattern> [lines]" >&2
        return 1
    fi
    _rawlog "$1" "${2:-20}"
}

# Follow the log live, optionally filtered: `logf` or `logf "EVM transaction"`.
# Ctrl-c to stop.
logf() {
    tail -n 0 -f "$NODE_LOG" | grep -a -E --color=always --line-buffered "${1:-.}"
}

# What to run right now: the demo publishes STEP as it pauses, so this
# tracks whichever step you are on.
step() {
    _demo_load || return 1
    echo "the demo is paused after STEP ${STEP:-0}. Worth running here:"
    echo
    case "${STEP:-0}" in
    0)
        echo "  chain      # epoch 3.3, tip height -- a real booted chain"
        echo "  balances   # the sender is funded; no EVM contracts exist yet"
        ;;
    1)
        echo "  evmlog     # the node's own log line: the EVM deploying the contract"
        echo "  addrs      # the EVM contract now has a Stacks principal"
        echo "  balances   # ...and its balance is still 0 (nothing sent yet)"
        ;;
    2)
        echo "  balances   # <- the money shot: 5 STX now sits in the EVM contract"
        echo "  evmlog     # raw log: payload EvmContractCall, gas_used, succeeded"
        echo "  signerlog  # the signers accepting the block that carried it"
        echo "  evm-events # the Solidity log event, topic decoded"
        ;;
    3)
        echo "  chain      # the tip advanced; each step is a real mined block"
        echo "  blocklog   # raw log: blocks moving through the node"
        echo "  rpclog     # raw log: the demo's POST /v2/transactions"
        echo "  txs        # every tx mined so far, with status + result"
        ;;
    4)
        echo "  oracle     # call-read the Clarity fn the EVM is about to read"
        echo "  src \$ORACLE # its Clarity source, as stored on chain"
        ;;
    5)
        echo "  oracle     # the EVM just read exactly this value (u42)"
        ;;
    6)
        echo "  events     # BOTH: the EVM's log and Clarity's print of the response"
        echo "  evmlog     # raw log: the EVM ran, driven from Clarity this time"
        echo "  src \$CALLER # real (evm-call? ...) Clarity source, on chain"
        echo "  balances   # the Clarity contract paid the EVM from its OWN balance"
        ;;
    7)
        echo "  balances   # vault holds 5 STX (from the EVM) + 1 STX (from Clarity)"
        echo "  evmlog     # the whole run, as the node logged it"
        echo "  txs        # every transaction the demo mined"
        ;;
    *)
        echo "  balances ; chain"
        ;;
    esac
}

help() {
    cat <<'EOF'
EVM-on-Stacks demo -- RPC pane

  step       what to run right now (tracks the demo's current step)  <- start here
  balances   one table: sender / EVM contract / Clarity contract, in uSTX
  addrs      every address the demo has published so far
  chain      chain tip / epoch summary             (GET /v2/info)
  vault      the EVM contract's STX balance        <- "1 wei == 1 uSTX"
  caller     the Clarity contract driving the EVM  (its balance funds msg.value)
  sender     the demo sender's balance + nonce     (GET /v2/accounts)
  oracle     read the Clarity oracle the EVM calls (POST call-read)
  src [id]   a contract's Clarity source, on chain (GET /v2/contracts/source)
  acct <p>   balance + nonce for any principal
  tx <txid>  fetch a transaction
  watch-balances   live balance table (Ctrl-c to stop)

 raw node log (the node's actual output, match highlighted):
  evmlog [n]     the EVM running: payload type, gas used, succeeded, address
  signerlog [n]  signers accepting the block that carried the transaction
  blocklog [n]   blocks moving through the node
  rpclog [n]     HTTP the node served (incl. the demo's POST /v2/transactions)
  logs <pat> [n] grep the log for anything
  logf [pat]     follow the log live, filtered (Ctrl-c to stop)

 parsed from the node's event stream (snapshotted at each pause):
  txs [n]        recent transactions: status, txid, result
  events [n]     recent events of every kind
  evm-events     EVM logs only, with the Solidity topic decoded
  blocks [n]     per-block height / tx count / event count

The walkthrough pane prints the commands worth running at each pause; `step`
repeats them here.
EOF
}

echo "EVM-on-Stacks demo RPC pane. Type 'help' for available commands."
