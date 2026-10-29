#!/usr/bin/env bash
# Translate action inputs (environment variables) into depradar-ci arguments.
# The exit code is recorded as an output and enforced by a later step, after SARIF upload.
set -uo pipefail

python_bin="$(command -v python3 || command -v python || true)"
if [[ -z "$python_bin" ]]; then
  echo "::error title=DepRadar::Python 3.9 or newer is required; add actions/setup-python before this action."
  printf 'result=error\nexit-code=2\n' >> "$GITHUB_OUTPUT"
  exit 0
fi
client="$GITHUB_ACTION_PATH/../../backend/src/depradar/ci_client.py"

args=(scan --mode "$INPUT_MODE" --fail-on "$INPUT_FAIL_ON" --timeout "$INPUT_TIMEOUT"
  --sarif "$INPUT_SARIF_FILE" --json "${RUNNER_TEMP:-/tmp}/depradar-gate.json")
[[ -n "$INPUT_PROJECT" ]] && args+=(--project "$INPUT_PROJECT")
[[ "$INPUT_CREATE_PROJECT" == "true" ]] && args+=(--create-project)
[[ "$INPUT_FAIL_ON_KEV" == "false" ]] && args+=(--no-fail-on-kev)
[[ "$INPUT_FAIL_ON_UNKNOWN" == "true" ]] && args+=(--fail-on-unknown)
[[ -n "$INPUT_EPSS_THRESHOLD" ]] && args+=(--epss-threshold "$INPUT_EPSS_THRESHOLD")
[[ "$INPUT_NEW_ONLY" == "true" ]] && args+=(--new-only)
[[ "$INPUT_IGNORE_ACKNOWLEDGED" == "true" ]] && args+=(--ignore-acknowledged)
[[ "$INPUT_FAIL_ON_INCOMPLETE" == "true" ]] && args+=(--fail-on-incomplete)
[[ -n "$INPUT_CA_FILE" ]] && args+=(--ca-file "$INPUT_CA_FILE")
[[ "$INPUT_ALLOW_INSECURE_HTTP" == "true" ]] && args+=(--allow-insecure-http)
while IFS= read -r pattern; do
  [[ -n "$pattern" ]] && args+=(--exclude "$pattern")
done <<< "$INPUT_EXCLUDE"
read -r -a paths <<< "$INPUT_PATHS"

"$python_bin" -I "$client" "${args[@]}" ${paths[@]+"${paths[@]}"}
code=$?
case "$code" in
  0) result=pass ;;
  1) result=fail ;;
  *) result=error ;;
esac
{
  echo "result=$result"
  echo "exit-code=$code"
  echo "sarif-file=$INPUT_SARIF_FILE"
} >> "$GITHUB_OUTPUT"
