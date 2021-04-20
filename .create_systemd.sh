#!/usr/bin/env sh
echo "[Unit]
Description=The tzchat server
After=network-online.target

[Install]
WantedBy=multi-user.target

[Service]
Type=simple
WorkingDirectory=$(pwd)
ExecStart=$HOME/.cargo/bin/cargo start" > ~/.local/share/systemd/user/tzchat.service
