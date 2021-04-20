#!/usr/bin/env bash

source $HOME/.profile

echo $TZ_CLIENT_ID

echo "[Unit]
Description=The tzchat server
After=network-online.target

[Install]
WantedBy=multi-user.target

[Service]
Environment=TZ_CLIENT_ID=$TZ_CLIENT_ID
Environment=TZ_SECRET=$TZ_SECRET
Environment=SSL_CERT_PATH=$SSL_CERT_PATH
Environment=SSL_KEY_PATH=$SSL_KEY_PATH
Type=simple
WorkingDirectory=$(pwd)
ExecStart=$HOME/.cargo/bin/cargo run" > ~/.local/share/systemd/user/tzchat.service
