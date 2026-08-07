#!/usr/bin/env bash
#
# Entrypoint for the EVM-on-Stacks demo container. Runs the narrated
# `evm_demo` integration test.
#
# In a test build the node/signer logger writes to *stdout*, while the demo
# writes its walkthrough panels to *stderr*. So capture stdout to keep the
# terminal showing only the panels, with full logs preserved in the file:
#
#   podman run --rm -it evm-demo 1>node.log
set -euo pipefail

export BITCOIND_TEST=1

exec cargo test -p stacks-node --offline evm_demo -- \
    --ignored --nocapture --test-threads=1
