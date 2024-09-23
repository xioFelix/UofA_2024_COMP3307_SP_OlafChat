#!/bin/bash
# Add project root to PYTHONPATH to make sure Python can find the modules
export PYTHONPATH=$(pwd)
python3 ./server/server.py --host 127.0.0.1 --port 8080 --server_port 8081
python3 ./server/server.py --host 127.0.0.1 --port 8082 --server_port 8083
