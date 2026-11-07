#!/usr/bin/env bash
# Write one key of a service's config secret ({service}/live-config or
# {service}/test-config): one JSON object, one snake_case key per value, read
# at cold start by platform_secrets::load (shared-rust#4; protocols
# docs/adr-secret-storage.md). Terraform declares the secret but never its
# value; this script is the writer.
#
#   put-config-key.sh <secret-id> <key>     # the value on stdin, or typed at
#                                           # the prompt (not echoed)
#   put-config-key.sh <secret-id> --list    # key names only
#
# `<key>` replaces that key and keeps every other one. An empty value is
# refused: to make a key absent, write the code that no longer needs it.
#
# No value is ever printed, logged, written to a file, or passed as a command
# argument (argv is visible to other local processes). Values move only through
# shell variables, the printf builtin, and pipes into jq and
# `aws ... file:///dev/stdin`. Only key NAMES are printed.
#
# Credentials and region come from the usual AWS environment (AWS_PROFILE,
# AWS_REGION, default us-east-1).
set -euo pipefail
shopt -s inherit_errexit # a failed read inside $(...) must stop the script too
set +x                   # a trace would print values

export AWS_REGION="${AWS_REGION:-us-east-1}"

usage() {
  echo "usage: $0 <secret-id> <key> | $0 <secret-id> --list" >&2
  exit 2
}

[ $# = 2 ] || usage
SECRET_ID="$1"
ACTION="$2"

for tool in aws jq; do
  command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 1; }
done

# The secret's current value, or {} while it has none. Holds every value:
# never echo it.
read_secret() {
  local out
  if out="$(aws secretsmanager get-secret-value --secret-id "$SECRET_ID" \
    --query SecretString --output text 2>&1)"; then
    printf '%s' "$out"
  elif grep -q "ResourceNotFoundException" <<<"$out" && grep -q "AWSCURRENT" <<<"$out"; then
    printf '{}' # declared by Terraform, no value written yet
  else
    # A failed call's output is the CLI's error text, which carries no value.
    echo "get-secret-value $SECRET_ID failed:" >&2
    echo "$out" >&2
    return 1
  fi
}

# Every key, with whether its value is non-blank (platform-secrets reads a
# blank value as absent). Names only.
list_keys() {
  jq -r 'to_entries[] | "\(.key)\t\(if (.value | type) == "string" and (.value | test("\\S")) then "set" else "blank or not a string" end)"'
}

echo "account $(aws sts get-caller-identity --query Account --output text), region $AWS_REGION, secret $SECRET_ID" >&2
current="$(read_secret)"
printf '%s' "$current" | jq -e 'type == "object"' >/dev/null || { echo "$SECRET_ID is not a JSON object" >&2; exit 1; }

case "$ACTION" in
  --list) ;;
  -*) usage ;;
  *)
    key="$ACTION"
    [[ "$key" =~ ^[a-z][a-z0-9_]*$ ]] || { echo "key $key is not snake_case" >&2; exit 2; }
    if [ -t 0 ]; then
      IFS= read -rs -p "value for $key: " value
      echo >&2
    else
      value="$(cat)"
    fi
    [[ "$value" =~ [^[:space:]] ]] || { echo "empty value; nothing written" >&2; exit 1; }
    # Both documents go through stdin: .[0] the secret, .[1] the new value.
    { printf '%s\n' "$current"; printf '%s' "$value" | jq -Rs .; } \
      | jq -cs --arg k "$key" '.[0] + {($k): .[1]}' \
      | aws secretsmanager put-secret-value --secret-id "$SECRET_ID" --secret-string file:///dev/stdin >/dev/null
    unset value
    echo "put $key" >&2
    current="$(read_secret)" # read back, so the list below is what is stored
    ;;
esac

printf '%s' "$current" | list_keys
unset current
