#!/bin/bash

#
PORT=$1
URL=192.168.122.5
METHOD=POST
USING_URL=${URL}
USING_PORT=${PORT}
USING_RESTFUL=${METHOD}

#
COMMAND="${USING_RESTFUL} http://${USING_URL}:${USING_PORT}/sw/api/v1/container/cancel"

#
RESPONSE=$(curl -s --location --request ${COMMAND} \
	--header 'Authorization: ' \
	--data-raw '')


# JSON fields
ERROR_CODE=$(echo "$RESPONSE" | jq -r '.code // 0' 2>/dev/null || echo "0")
MESSAGE=$(echo "$RESPONSE" | jq -r '.message // "No message"' 2>/dev/null || echo "No message")

# Result
if [ "$ERROR_CODE" -eq 200 ]; then
    echo "✅ $COMMAND: Success (code: $ERROR_CODE)"
    echo "Response: $RESPONSE"
else
    echo "❌ $COMMAND: Failed (code: $ERROR_CODE)"
    echo "Response: $RESPONSE"
    exit 1
fi