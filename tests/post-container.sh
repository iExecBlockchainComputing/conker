#!/bin/bash

#
URL_3=145.239.161.248
PORT_7=3333

#
PORT=$1
URL=192.168.122.5
METHOD=POST
USING_URL=${URL}
USING_PORT=${PORT}
USING_RESTFUL=${METHOD}



#
COMMAND="${USING_RESTFUL} http://${USING_URL}:${USING_PORT}/sw/api/v1/container"

#
JSON_BODY=$(
	cat <<EOF
{
    "Name": "conker-example-app",
    "ImageInfo": {
        "ImageName": "iexechub/python-hello-world:8.0.4",
        "RegisterAuthInfo": {
            "Username": "",
            "Password": ""
        },
		"Cmd": "python /app/app.py",
		"MaxExecutionTime": 1000
    },
    "Ports": [
        {
            "TargetPort": 8080,
            "PublishedPort": 30001
        }
    ],
    "Env": [
        "userId=secret-${URL_3}:${PORT_7}"
    ],
    "Mounts": [
        {
			"Type": "bind",
			"Target": "/iexec_in",
			"Source": "/iexec_in",
			"RW": false
			},
			{
			"Type": "bind",
			"Target": "/iexec_out",
			"Source": "/iexec_out",
			"RW": true
		}
    ],
    "KmsEndpoints": [
        "${URL_3}:${PORT_7}"
    ],
	"SessionId": "2lVUIyHQLY00000xcb514ee3b79fda871c8a97376461cd646a9c2fb49422412a18433249597c6603",
	"WorkerHost": "test"
}
EOF
)

RESPONSE=$(curl -s --location --request ${COMMAND} \
	--header 'Authorization: ' \
	--header 'Content-Type: application/json' \
	--data-raw "${JSON_BODY}")


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