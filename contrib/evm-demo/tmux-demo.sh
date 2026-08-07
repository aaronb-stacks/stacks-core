#!/usr/bin/env bash
#
# Launch the EVM-on-Stacks demo in a three-pane tmux window:
#
#   +---------------------------+---------------------------+
#   |  demo walkthrough         |  node / signer / bitcoind |
#   |  (stderr)                 |  logs (stdout)            |
#   |  <- press Enter here      |                           |
#   +---------------------------+---------------------------+
#   |  RPC shell: curl + jq against the running node        |
#   +-------------------------------------------------------+
#
# The stream split happens *inside* this script (stdout is redirected to a
# log file, stderr stays on the pane), so it does not matter that tmux runs
# under a pseudo-TTY.
#
# Focus the top-left pane to advance the demo. Switch panes with Ctrl-b then
# an arrow key (mouse click also works; mouse mode is enabled below).
set -euo pipefail

SESSION="${SESSION:-evm-demo}"
WORKDIR="${WORKDIR:-/tmp/evm-demo}"
NODE_LOG="$WORKDIR/node.log"
DEMO_ENV="$WORKDIR/rpc.env"
HELPERS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/rpc-helpers.sh"
SRC_DIR="${SRC_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

# Resolve cargo up front and carry this PATH into every pane. A login shell
# (`bash -l`) would re-source /etc/profile and drop the toolchain's PATH, so
# the panes below use plain `bash -c` with PATH passed through explicitly.
if ! command -v cargo >/dev/null 2>&1; then
    echo "error: cargo is not on PATH ($PATH)" >&2
    echo "       run this from an environment where 'cargo --version' works." >&2
    exit 1
fi
DEMO_PATH="$PATH"

mkdir -p "$WORKDIR"
: >"$NODE_LOG"
: >"$DEMO_ENV"

if tmux has-session -t "$SESSION" 2>/dev/null; then
    tmux kill-session -t "$SESSION"
fi

# The demo itself: panels on stderr (this pane), logs on stdout (the file the
# top-right pane tails). EVM_DEMO_RPC_FILE tells the test where to publish its
# endpoint and the addresses it creates, for the RPC pane to query.
DEMO_CMD="export PATH='$DEMO_PATH'; cd '$SRC_DIR' && \
BITCOIND_TEST=1 EVM_DEMO_RPC_FILE='$DEMO_ENV' \
cargo test -p stacks-node --offline evm_demo -- \
    --ignored --nocapture --test-threads=1 \
    1>'$NODE_LOG'; \
echo; echo '[demo finished -- press Enter to close this pane]'; read -r"

# pane 1 (top-left): the demo; stdin is connected here, so Enter advances it
tmux new-session -d -s "$SESSION" -n demo "bash -c \"$DEMO_CMD\""
DEMO_PANE="$(tmux list-panes -t "$SESSION:demo" -F '#{pane_id}' | head -n1)"

# pane 2 (bottom, full width): the interactive RPC shell
tmux split-window -v -l '30%' -t "$DEMO_PANE" \
    "bash -c \"export PATH='$DEMO_PATH'; cd '$WORKDIR' && DEMO_ENV='$DEMO_ENV' bash --rcfile '$HELPERS' -i\""

# pane 3 (top-right): the node logs
tmux split-window -h -l '50%' -t "$DEMO_PANE" \
    "bash -c \"tail -n +1 -f '$NODE_LOG'\""

tmux set-option -t "$SESSION" -g mouse on
tmux set-option -t "$SESSION" -g history-limit 50000
tmux select-pane -t "$DEMO_PANE"

exec tmux attach-session -t "$SESSION"
