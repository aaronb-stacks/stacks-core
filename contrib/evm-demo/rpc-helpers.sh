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

help() {
    cat <<'EOF'
EVM-on-Stacks demo -- RPC pane

  addrs      show every address the demo has published so far
  chain      chain tip / epoch summary            (GET /v2/info)
  sender     the demo sender's balance + nonce    (GET /v2/accounts)
  vault      the EVM contract's STX balance       <- "1 wei == 1 uSTX"
  caller     the Clarity contract driving the EVM (its balance funds msg.value)
  oracle     read the Clarity oracle the EVM calls (POST call-read)
  acct <p>   balance + nonce for any principal
  tx <txid>  fetch a transaction
  help       this message

Suggested moments to run these (while the demo is paused for Enter):
  after STEP 1  -> addrs ; vault      (contract exists, balance still 0)
  after STEP 2  -> vault ; sender     (5 STX moved into the EVM contract)
  after STEP 4  -> oracle             (the Clarity value the EVM will read)
  after STEP 6  -> caller ; vault     (Clarity paid the EVM out of its own balance)
EOF
}

echo "EVM-on-Stacks demo RPC pane. Type 'help' for available commands."
