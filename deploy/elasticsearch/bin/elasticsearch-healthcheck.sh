#!/bin/sh

set -u

CA_CERT='/usr/share/elasticsearch/config/certs/ca/ca.crt'
PASSWORD_FILE='/run/secrets/elasticsearch-bootstrap-password'
HEALTH_URL='https://elasticsearch:9200/_cluster/health?wait_for_status=yellow&timeout=5s&filter_path=status,timed_out'
RESPONSE_FILE=''

cleanup() {
  if [ -n "$RESPONSE_FILE" ] && [ -f "$RESPONSE_FILE" ]; then
    rm -f -- "$RESPONSE_FILE"
  fi
}

fail() {
  cleanup
  exit 1
}

trap cleanup EXIT HUP INT TERM

[ -r "$CA_CERT" ] || fail
[ -r "$PASSWORD_FILE" ] || fail

IFS= read -r password < "$PASSWORD_FILE" || fail
[ -n "$password" ] || fail

escaped_password=$(printf '%s' "$password" | sed 's/\\/\\\\/g; s/"/\\"/g') || fail
unset password

RESPONSE_FILE=$(mktemp /tmp/aegis-es-health.XXXXXX) || fail

http_code=$(
  {
    printf '%s\n' 'silent'
    printf '%s\n' 'fail'
    printf '%s\n' 'request = "GET"'
    printf 'cacert = "%s"\n' "$CA_CERT"
    printf 'user = "elastic:%s"\n' "$escaped_password"
    printf 'url = "%s"\n' "$HEALTH_URL"
    printf 'output = "%s"\n' "$RESPONSE_FILE"
    printf '%s\n' 'write-out = "%{http_code}"'
    printf '%s\n' 'connect-timeout = "3"'
    printf '%s\n' 'max-time = "8"'
  } | curl --config - 2>/dev/null
) || fail
unset escaped_password

[ "$http_code" = '200' ] || fail

compact_response=$(tr -d '[:space:]' < "$RESPONSE_FILE") || fail
case "$compact_response" in
  '{"status":"yellow","timed_out":false}'|'{"status":"green","timed_out":false}'|'{"timed_out":false,"status":"yellow"}'|'{"timed_out":false,"status":"green"}')
    cleanup
    trap - EXIT HUP INT TERM
    exit 0
    ;;
  *)
    fail
    ;;
esac
