#!/bin/bash

# Load environment variables saved by entrypoint
source /etc/spawn.env

# CTFD_INSTANCES format: "name1|url1|apikey1,name2|url2|apikey2,..."
CHALLENGE_NAME="old-days"

# Prompt for CTFd API token
echo -n "Enter your CTFd API Token: "
read -r USER_TOKEN

if [ -z "$USER_TOKEN" ]; then
    echo "Error: No token provided."
    exit 1
fi

if [ "$USER_TOKEN" = "local" ]; then
    INST_NAME="local"
    TEAM_ID="1"
    TEAM_NAME="local"
    USER_NAME="local"
else    # start of non-local token context

if [ -z "$CTFD_INSTANCES" ]; then
    echo "Error: No CTFd instances configured."
    exit 1
fi

# Try each CTFd instance until we find a match
MATCHED=0
IFS=',' read -ra INSTANCES <<< "$CTFD_INSTANCES"
for INSTANCE in "${INSTANCES[@]}"; do
    IFS='|' read -r INST_NAME INST_URL INST_API_KEY <<< "$INSTANCE"

    # Verify user token against this instance
    USER_RESP=$(curl -s -L -m 10 -w "\n%{http_code}" \
        -H "Authorization: Token ${USER_TOKEN}" \
        -H "Content-Type: application/json" \
        "${INST_URL}/api/v1/users/me")

    HTTP_CODE=$(echo "$USER_RESP" | tail -1)
    USER_JSON=$(echo "$USER_RESP" | sed '$d')

    [ "$HTTP_CODE" != "200" ] && continue

    # Extract team_id
    TEAM_ID=$(echo "$USER_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data']['team_id'])" 2>/dev/null)
    USER_NAME=$(echo "$USER_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data']['name'])" 2>/dev/null)

    [ -z "$TEAM_ID" ] || [ "$TEAM_ID" = "None" ] || [ "$TEAM_ID" = "null" ] && continue

    # Verify team exists via admin API
    TEAM_RESP=$(curl -s -L -m 10 -w "\n%{http_code}" \
        -H "Authorization: Token ${INST_API_KEY}" \
        -H "Content-Type: application/json" \
        "${INST_URL}/api/v1/teams/${TEAM_ID}")

    TEAM_HTTP=$(echo "$TEAM_RESP" | tail -1)
    TEAM_JSON=$(echo "$TEAM_RESP" | sed '$d')

    [ "$TEAM_HTTP" != "200" ] && continue

    TEAM_NAME=$(echo "$TEAM_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data']['name'])" 2>/dev/null)
    MATCHED=1
    break
done

if [ "$MATCHED" -ne 1 ]; then
    echo "Error: Invalid token, or you do not belong to a team."
    exit 1
fi

fi  # end of non-local token context

# Sanitize instance name for container naming (lowercase, alphanumeric+dash only)
SAFE_INST=$(echo "$INST_NAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g')
CONTAINER_NAME="${CHALLENGE_NAME}-${SAFE_INST}-team-${TEAM_ID}"

echo "Authenticated as '${USER_NAME}' / team '${TEAM_NAME}' (${INST_NAME})"

SESSION_TIMEOUT=60

start_timeout_watchdog() {
    (
        sleep "$SESSION_TIMEOUT"
        echo -e "\r\n\r\n[!] ${SESSION_TIMEOUT}s time limit reached. Terminating session..."
        docker kill "$CONTAINER_NAME" >/dev/null 2>&1
    ) &
    TIMER_PID=$!
}

cleanup_timer() {
    kill "$TIMER_PID" 2>/dev/null
    wait "$TIMER_PID" 2>/dev/null
}
trap cleanup_timer EXIT

# Check if a container already exists for this team
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    STATE=$(docker inspect -f '{{.State.Status}}' "$CONTAINER_NAME" 2>/dev/null)

    if [ "$STATE" = "running" ]; then
        echo "Connecting to existing instance..."
        start_timeout_watchdog
        docker exec -it "$CONTAINER_NAME" /bin/bash
    else
        docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1
        echo "Starting new instance..."
        start_timeout_watchdog
        docker run --rm -it \
            --name "$CONTAINER_NAME" \
            --network none \
            --memory 128m \
            --cpus 0.5 \
            --pids-limit 64 \
            "$CHALLENGE_NAME-inner"
    fi
else
    echo "Starting new instance..."
    start_timeout_watchdog
    docker run --rm -it \
        --name "$CONTAINER_NAME" \
        --network none \
        --memory 128m \
        --cpus 0.5 \
        --pids-limit 64 \
        "$CHALLENGE_NAME-inner"
fi
