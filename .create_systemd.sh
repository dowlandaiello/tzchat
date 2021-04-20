#!/usr/bin/env sh
echo "[Unit]
Description=The tzchat server\n \
After=network-online.target\n \

[Install]
WantedBy=multi-user.target

[Service]
User=$(whoami)
Type=simple
WorkingDirectory=$(pwd)
ExecStart=$HOME/.cargo/bin/cargo start"
