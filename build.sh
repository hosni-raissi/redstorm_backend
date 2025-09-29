#!/bin/bash
# setup-venv.sh - Simple RedStorm Virtual Environment Setup

set -e

# Create virtual environment
python3 -m venv redstorm-env

# Activate virtual environment
if [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "win32" ]]; then
    # Windows
    source redstorm-env/bin/activate
else
    # Linux/Mac
    source redstorm-env/bin/activate
fi

# Install requirements
pip install -r requirements.txt
cd tools
# Build the tool
go build -o redstorm-tools .
# 2. start OpenVAS container (only first time)
docker run -d --name gvm -p 9392:9392 securecompliance/gvm:latest
cd ..
# laptop on same Wi-Fi
python ws_client.py  ws://10.156.85.210:8000/ws/demo-$$

echo "Virtual environment setup complete!"
echo "To activate: source redstorm-env/bin/activate"