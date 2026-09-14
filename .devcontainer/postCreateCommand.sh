#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

echo "Updating package lists..."
sudo apt-get update

echo "Installing xclip..."
sudo apt-get install -y \
    xclip \
    git-crypt

# echo "downloading Opencode"
# curl -fsSL https://opencode.ai/install | bash

echo "getting latest node.js 25"
curl -fsSL https://deb.nodesource.com/setup_25.x | sudo -E bash -
sudo apt-get install -y nodejs
node -v

# make node "global modules" be installed in a local folder
mkdir ~/.npm-global
npm config set prefix '~/.npm-global'
echo 'export PATH=~/.npm-global/bin:$PATH' >> ~/.bashrc && source ~/.bashrc


echo "downloading pi.dev"
npm install -g --ignore-scripts @earendil-works/pi-coding-agent
