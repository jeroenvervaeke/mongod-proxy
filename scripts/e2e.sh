#!/usr/bin/env bash
# End-to-end test: spin up MongoDB in Docker, run the logger example as proxy,
# drive it with mongosh, and assert that the proxy's log file captured the
# expected request/response traffic.
#
# Tested on Linux with `--network host`. macOS/Windows users will need to map
# ports explicitly and target `host.docker.internal` from inside mongosh.
#
# Notes on Atlas sample data: the `mongodb/mongodb-atlas-local` image does NOT
# ship the Atlas cloud sample dataset preloaded. This script seeds a synthetic
# dataset large enough to force multi-batch (multi-message) cursor responses,
# which is what we need to prove the proxy parses streamed replies correctly.

set -euo pipefail

MONGO_IMAGE="${MONGO_IMAGE:-mongodb/mongodb-atlas-local:latest}"
MONGO_PORT="${MONGO_PORT:-27017}"
PROXY_PORT="${PROXY_PORT:-27018}"
MONGO_CONTAINER="mongod-proxy-e2e-mongo"
PROXY_PID=""
LOG_FILE="$(mktemp -t mongod-proxy-e2e.XXXXXX.log)"
ARTIFACTS_DIR="${ARTIFACTS_DIR:-$(pwd)/target/e2e}"

mkdir -p "$ARTIFACTS_DIR"

PHASE_START=""
TOTAL_START=$(date +%s%N)
log() {
    local now elapsed_total elapsed_phase
    now=$(date +%s%N)
    elapsed_total=$(awk -v a="$now" -v b="$TOTAL_START" 'BEGIN { printf "%.2f", (a-b)/1e9 }')
    if [[ -n "$PHASE_START" ]]; then
        elapsed_phase=$(awk -v a="$now" -v b="$PHASE_START" 'BEGIN { printf "%.2f", (a-b)/1e9 }')
        printf '\033[1;34m[e2e %6.2fs +%s]\033[0m %s\n' "$elapsed_total" "$elapsed_phase" "$*"
    else
        printf '\033[1;34m[e2e %6.2fs]\033[0m %s\n' "$elapsed_total" "$*"
    fi
    PHASE_START=$now
}
err() { printf '\033[1;31m[e2e]\033[0m %s\n' "$*" >&2; }

cleanup() {
    local exit_code=$?
    if [[ -n "$PROXY_PID" ]]; then
        kill "$PROXY_PID" 2>/dev/null || true
        wait "$PROXY_PID" 2>/dev/null || true
    fi
    docker rm -f "$MONGO_CONTAINER" >/dev/null 2>&1 || true
    cp "$LOG_FILE" "$ARTIFACTS_DIR/proxy.log" 2>/dev/null || true
    log "proxy log saved to $ARTIFACTS_DIR/proxy.log (raw: $LOG_FILE)"
    exit "$exit_code"
}
trap cleanup EXIT

require_cmd() {
    command -v "$1" >/dev/null || { err "missing required command: $1"; exit 2; }
}

mongosh_in_container() {
    # Run mongosh from inside the mongo container; with --network host this
    # reaches both mongod (127.0.0.1:$MONGO_PORT) and the proxy (127.0.0.1:$PROXY_PORT).
    docker exec -i "$MONGO_CONTAINER" mongosh --quiet "$@"
}

require_cmd docker
require_cmd cargo

log "starting mongo container ($MONGO_IMAGE)"
docker rm -f "$MONGO_CONTAINER" >/dev/null 2>&1 || true
CONTAINER_ID=$(docker run -d --rm \
    --name "$MONGO_CONTAINER" \
    --network host \
    -e MONGOT_DISABLED=true \
    "$MONGO_IMAGE")
log "container id: ${CONTAINER_ID:0:12}"

log "waiting for mongod on 127.0.0.1:${MONGO_PORT}"
for attempt in $(seq 1 600); do
    if mongosh_in_container --host "127.0.0.1:${MONGO_PORT}" --eval 'db.runCommand({ ping: 1 })' >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
    if [[ $attempt -eq 600 ]]; then
        err "mongod never became ready"
        docker logs "$MONGO_CONTAINER" >&2 || true
        exit 1
    fi
done

# Capture mongod version + uptime to prove this is a real fresh boot.
MONGO_INFO=$(mongosh_in_container --host "127.0.0.1:${MONGO_PORT}" --eval '
const bi = db.runCommand({ buildInfo: 1 });
const ss = db.runCommand({ serverStatus: 1 });
print("version=" + bi.version + " uptime_seconds=" + ss.uptime + " pid=" + ss.pid);
' 2>/dev/null | tr -d '\r')
log "mongod ready: $MONGO_INFO"

log "seeding test data"
mongosh_in_container --host "127.0.0.1:${MONGO_PORT}" >/dev/null <<'EOF'
const sampleDb = db.getSiblingDB('sample');
sampleDb.movies.drop();
const docs = [];
const genres = ['drama', 'comedy', 'action', 'sci-fi', 'horror', 'documentary'];
for (let i = 0; i < 500; i++) {
    docs.push({
        _id: i,
        title: `Movie ${i}`,
        year: 1980 + (i % 45),
        genre: genres[i % genres.length],
        rating: Math.round(((i % 100) / 10) * 10) / 10,
        tags: [`tag-${i % 7}`, `tag-${i % 11}`, `tag-${i % 13}`],
    });
}
sampleDb.movies.insertMany(docs);
print('seeded ' + sampleDb.movies.countDocuments() + ' documents');
EOF

log "building logger (release)"
cargo build --release -p logger >/dev/null

log "starting proxy on 127.0.0.1:${PROXY_PORT}"
MONGOD_PROXY_LISTEN="127.0.0.1:${PROXY_PORT}" \
MONGOD_PROXY_UPSTREAM_HOST="127.0.0.1" \
MONGOD_PROXY_UPSTREAM_PORT="${MONGO_PORT}" \
MONGOD_PROXY_TLS="false" \
RUST_LOG="${RUST_LOG:-debug}" \
    cargo run --release -q -p logger >"$LOG_FILE" 2>&1 &
PROXY_PID=$!

for attempt in $(seq 1 60); do
    if (exec 3<>/dev/tcp/127.0.0.1/"${PROXY_PORT}") 2>/dev/null; then
        exec 3>&- 3<&-
        break
    fi
    if ! kill -0 "$PROXY_PID" 2>/dev/null; then
        err "proxy exited before binding; tail of log:"
        tail -50 "$LOG_FILE" >&2 || true
        exit 1
    fi
    sleep 0.25
    if [[ $attempt -eq 60 ]]; then
        err "proxy never bound on ${PROXY_PORT}"
        exit 1
    fi
done

log "driving traffic through the proxy"
set +e
mongosh_in_container --host "127.0.0.1:${PROXY_PORT}" >/dev/null <<'EOF'
const sampleDb = db.getSiblingDB('sample');
sampleDb.runCommand({ hello: 1 });
sampleDb.movies.findOne();
sampleDb.movies.find({ genre: 'drama' }).limit(10).toArray();
// 500 documents at default batchSize 101 forces multiple getMore round-trips
// so the proxy must handle several request/response pairs back-to-back.
const all = sampleDb.movies.find().toArray();
print('full scan length: ' + all.length);
sampleDb.movies.aggregate([
    { $group: { _id: '$genre', n: { $sum: 1 } } },
    { $sort: { _id: 1 } },
]).toArray();
sampleDb.movies.countDocuments();
EOF
mongosh_rc=$?
set -e

# Give the proxy a moment to flush its last response log line.
sleep 0.5
kill -TERM "$PROXY_PID" 2>/dev/null || true
wait "$PROXY_PID" 2>/dev/null || true
PROXY_PID=""

if [[ $mongosh_rc -ne 0 ]]; then
    err "mongosh exited with status $mongosh_rc"
    tail -100 "$LOG_FILE" >&2 || true
    exit 1
fi

log "verifying proxy captured expected traffic"
# Strip any stray ANSI escapes so assertions don't have to care about them.
CLEAN_LOG="${ARTIFACTS_DIR}/proxy.clean.log"
sed -E 's/\x1B\[[0-9;]*[A-Za-z]//g' "$LOG_FILE" > "$CLEAN_LOG"

fail=0
require_token() {
    local pattern="$1"
    local label="$2"
    if ! grep -qF "$pattern" "$CLEAN_LOG"; then
        err "FAIL: log missing $label (substring: $pattern)"
        fail=1
    fi
}

require_token 'received request'    'request log line'
require_token 'received response'   'response log line'
require_token 'OP_MSG'              'OP_MSG operation tag'
require_token '"find"'              'find command in captured body'
require_token '"getMore"'           'getMore command (proves multi-batch reply handling)'
require_token '"aggregate"'         'aggregate command'
require_token '"movies"'            'collection name in captured body'
require_token 'sample'              'database name in captured body'

requests=$(grep -c 'received request' "$CLEAN_LOG" || true)
responses=$(grep -c 'received response' "$CLEAN_LOG" || true)
log "captured $requests requests / $responses responses"
if [[ "$requests" -lt 10 ]]; then
    err "FAIL: only $requests requests captured, expected at least 10"
    fail=1
fi
if [[ "$responses" -lt 10 ]]; then
    err "FAIL: only $responses responses captured, expected at least 10"
    fail=1
fi

if [[ $fail -ne 0 ]]; then
    err "--- proxy log (last 200 lines, ANSI stripped) ---"
    tail -200 "$CLEAN_LOG" >&2 || true
    exit 1
fi

log "OK: proxy captured all expected traffic patterns"
