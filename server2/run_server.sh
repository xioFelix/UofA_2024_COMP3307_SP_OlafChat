#!/bin/bash

# Usage: ./run_server.sh <ws_port> <http_port> [<neighbour1> <neighbour2> ...]

if [ "$#" -lt 2 ]; then
    echo "Usage: ./run_server.sh <ws_port> <http_port> [<neighbour1> <neighbour2> ...]"
    echo "Example: ./run_server.sh 8080 8000 localhost:8081 localhost:8082"
    exit 1
fi

WS_PORT=$1
HTTP_PORT=$2
shift 2
NEIGHBOURS=("$@")

# 运行服务器，传递邻居服务器地址
python3 server.py --ws_port $WS_PORT --http_port $HTTP_PORT --neighbours "${NEIGHBOURS[@]}"
