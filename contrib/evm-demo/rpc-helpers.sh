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
        echo "  addrs      # the EVM contract now has a Stacks principal"
        echo "  balances   # ...and its balance is still 0 (nothing sent yet)"
        ;;
    2)
        echo "  balances   # <- the money shot: 5 STX now sits in the EVM contract"
        echo "  vault      # same thing, straight from /v2/accounts"
        ;;
    3)
        echo "  chain      # the tip advanced; each step is a real mined block"
        echo "  balances   # unchanged: a read costs a fee but moves nothing"
        ;;
    4)
        echo "  oracle     # call-read the Clarity fn the EVM is about to read"
        echo "  src \$ORACLE # its Clarity source, as stored on chain"
        ;;
    5)
        echo "  oracle     # the EVM just read exactly this value (u42)"
        ;;
    6)
        echo "  src \$CALLER # real (evm-call? ...) Clarity source, on chain"
        echo "  balances   # the Clarity contract paid the EVM from its OWN balance"
        ;;
    7)
        echo "  balances   # vault holds 5 STX (from the EVM) + 1 STX (from Clarity)"
        ;;
    8)
        echo "  balances   # the revert moved nothing"
        echo "  sender     # ...but the nonce still advanced (fee paid)"
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

The walkthrough pane prints the commands worth running at each pause; `step`
repeats them here.
EOF
}

echo "EVM-on-Stacks demo RPC pane. Type 'help' for available commands."
