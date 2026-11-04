#!/usr/bin/env bash
# The alerting file as the install provisions it: @LARGEST_SLOT_MB@ filled in (the quoted one
# becomes a number). One place, for hack/install-monitoring.sh and for the alert checks.
set -euo pipefail
n=${1:?usage: render-alerting.sh LARGEST_SLOT_MB}
sed "s/\"@LARGEST_SLOT_MB@\"/$n/; s/@LARGEST_SLOT_MB@/$n/g" "$(dirname "$0")/monitoring/grafana/alerting.yaml"
