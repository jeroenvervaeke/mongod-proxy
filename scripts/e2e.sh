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
# Every command below MUST flow through the proxy. We deliberately use raw
# `runCommand` calls rather than the helper methods on Collection (findOne,
# insertMany, etc.) so that each command produces exactly one named OP_MSG
# request, the command name appearing in the proxy log is unambiguous, and
# explicit getMore round-trips are emitted.
#
# `directConnection=true` keeps the driver from doing replica-set topology
# discovery beyond the host we point it at. Streaming-SDAM (awaitable hello
# with EXHAUST_ALLOWED + moreToCome) is intentionally *left enabled* so the
# proxy's multi-reply handling gets exercised by every run.
PROXY_URI="mongodb://127.0.0.1:${PROXY_PORT}/?directConnection=true"
set +e
docker exec -i "$MONGO_CONTAINER" mongosh --quiet "$PROXY_URI" >/dev/null <<'EOF'
const adminDb = db.getSiblingDB('admin');
const sampleDb = db.getSiblingDB('sample');

// Handshake + server introspection
adminDb.runCommand({ hello: 1 });
adminDb.runCommand({ buildInfo: 1 });

// DDL: drop any leftover collections
sampleDb.runCommand({ drop: 'movies' });
sampleDb.runCommand({ drop: 'docs' });

// Inserts (multiple separate insert commands so we can count them)
const genres = ['drama', 'comedy', 'action', 'sci-fi', 'horror', 'documentary'];
const movies = [];
for (let i = 0; i < 500; i++) {
    movies.push({
        _id: i,
        title: `Movie ${i}`,
        year: 1980 + (i % 45),
        genre: genres[i % genres.length],
        rating: Math.round(((i % 100) / 10) * 10) / 10,
        tags: [`tag-${i % 7}`, `tag-${i % 11}`, `tag-${i % 13}`],
    });
}
sampleDb.runCommand({ insert: 'movies', documents: movies });
sampleDb.runCommand({ insert: 'docs', documents: [{ a: 1, label: 'one' }] });
sampleDb.runCommand({ insert: 'docs', documents: [{ a: 2, label: 'two' }] });

// Index management
sampleDb.runCommand({
    createIndexes: 'movies',
    indexes: [{ key: { genre: 1 }, name: 'genre_idx' }],
});
sampleDb.runCommand({ listIndexes: 'movies' });

// Metadata
sampleDb.runCommand({ listCollections: 1 });
adminDb.runCommand({ listDatabases: 1 });

// Reads. `singleBatch:false` keeps the cursor open so we can drive explicit
// getMore round-trips below. Small batchSize -> multiple getMore needed to
// drain 500 docs.
const findRes = sampleDb.runCommand({
    find: 'movies',
    batchSize: 50,
    singleBatch: false,
});
let cursorId = findRes.cursor.id;
print('initial batch length: ' + findRes.cursor.firstBatch.length);
while (cursorId && cursorId.toString() !== '0') {
    const next = sampleDb.runCommand({
        getMore: cursorId,
        collection: 'movies',
        batchSize: 50,
    });
    cursorId = next.cursor.id;
}

// Filtered find (just one batch needed for the drama subset)
sampleDb.runCommand({ find: 'movies', filter: { genre: 'drama' }, batchSize: 200 });

// Aggregation + count
sampleDb.runCommand({
    aggregate: 'movies',
    pipeline: [{ $group: { _id: '$genre', n: { $sum: 1 } } }, { $sort: { _id: 1 } }],
    cursor: {},
});
sampleDb.runCommand({ count: 'movies' });

// Mutations
sampleDb.runCommand({
    update: 'docs',
    updates: [{ q: { a: 1 }, u: { $set: { label: 'updated' } } }],
});
sampleDb.runCommand({
    update: 'docs',
    updates: [{ q: {}, u: { $set: { touched: true } }, multi: true }],
});
sampleDb.runCommand({
    delete: 'docs',
    deletes: [{ q: { a: 2 }, limit: 1 }],
});

// Cleanup drop (a second drop so the assert can expect drop>=2)
sampleDb.runCommand({ drop: 'movies' });
EOF
mongosh_rc=$?
set -e

# Allow the proxy time to flush the last response log line for fire-and-forget
# commands mongosh emits on exit (e.g. endSessions / killCursors).
sleep 2
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

# Count occurrences of a given (direction, command) pair on the structured
# log line. The LogService emits: `direction: "X", op: "...", command: "CMD", ...`
# in that order, so a regex anchored to both fields is robust.
count_dir_command() {
    local direction="$1" cmd="$2"
    grep -cE "direction: \"${direction}\", op: \"[A-Z_]+\", command: \"${cmd}\"" "$CLEAN_LOG" || true
}

# Note on response classification: OP_MSG responses carry result documents
# whose first BSON key is `cursor` / `ok` / `databases` / etc., not the
# command name. So we assert against the *request* side (where command name
# is unambiguous) and verify overall request/response parity separately.
expect_command() {
    local cmd="$1" min="$2"
    local req
    req=$(count_dir_command request "$cmd")
    printf '  %-18s requests=%-3s (min=%s)\n' "$cmd" "$req" "$min"
    if [[ "$req" -lt "$min" ]]; then
        err "FAIL: expected >=$min request(s) classified as command=$cmd, got $req"
        fail=1
    fi
}

log "per-command breakdown (commands classified by the proxy):"
# Commands we explicitly drove via mongosh. Minimums are conservative because
# mongosh + the server also emit driver-internal commands (extra hello / endSessions).
expect_command hello           1
expect_command buildInfo       1
expect_command drop            2
expect_command insert          3   # insertMany + 2x insertOne
expect_command createIndexes   1
expect_command listIndexes     1
expect_command find            2
expect_command getMore         3   # 500 docs / batch ~101 -> several getMore
expect_command aggregate       2   # explicit aggregate + countDocuments
expect_command count           1
expect_command update          2
expect_command delete          1
expect_command listCollections 1
expect_command listDatabases   1

# Op-code mix
op_msg_req=$(grep -cE 'direction: "request", op: "OP_MSG"' "$CLEAN_LOG" || true)
op_msg_resp=$(grep -cE 'direction: "response", op: "OP_MSG"' "$CLEAN_LOG" || true)
op_query_req=$(grep -cE 'direction: "request", op: "OP_QUERY"' "$CLEAN_LOG" || true)
op_reply_resp=$(grep -cE 'direction: "response", op: "OP_REPLY"' "$CLEAN_LOG" || true)
log "op-code mix: OP_MSG req=$op_msg_req resp=$op_msg_resp | OP_QUERY req=$op_query_req | OP_REPLY resp=$op_reply_resp"

if [[ "$op_msg_req" -lt 20 ]]; then
    err "FAIL: expected >=20 OP_MSG requests, got $op_msg_req"
    fail=1
fi
if [[ "$op_msg_resp" -lt 20 ]]; then
    err "FAIL: expected >=20 OP_MSG responses, got $op_msg_resp"
    fail=1
fi

# Sanity: every request should have a paired response (modulo fire-and-forget).
total_req=$(grep -c 'received request' "$CLEAN_LOG" || true)
total_resp=$(grep -c 'received response' "$CLEAN_LOG" || true)
log "total: requests=$total_req responses=$total_resp"
# Allow a small gap for endSessions / killCursors mongosh sends on exit.
gap=$(( total_req - total_resp ))
if (( gap < 0 )); then gap=$(( -gap )); fi
if (( gap > 4 )); then
    err "FAIL: request/response count imbalance too large ($total_req vs $total_resp)"
    fail=1
fi

if [[ $fail -ne 0 ]]; then
    err "--- proxy log (last 200 lines, ANSI stripped) ---"
    tail -200 "$CLEAN_LOG" >&2 || true
    exit 1
fi

log "OK: proxy correctly classified every expected command"
