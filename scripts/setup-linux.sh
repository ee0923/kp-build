#!/usr/bin/env bash
set -euo pipefail
sudo apt-get update
sudo apt-get install --yes --no-install-recommends \
  build-essential cmake ninja-build pkg-config asciidoctor \
  qt6-base-dev qt6-base-private-dev qt6-tools-dev qt6-tools-dev-tools \
  qt6-svg-dev qt6-5compat-dev qt6-wayland-dev libqt6svg6 \
  libbotan-2-dev libargon2-dev libminizip-dev libqrencode-dev libreadline-dev \
  libpcsclite-dev libusb-1.0-0-dev libxi-dev libxtst-dev libxkbcommon-dev \
  libxcb-cursor0 libudev-dev libdbus-1-dev libkeyutils-dev openssh-client xvfb xauth xclip dbus-x11
