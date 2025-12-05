#!/bin/bash
# Script to install and run codebuff to get auth URL

set -e

echo "=========================================="
echo "Codebuff Setup"
echo "=========================================="

# Load nvm
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
[ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion"

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "Node.js not found. Installing Node.js LTS..."
    nvm install --lts
    nvm use --lts
fi

echo "Node.js version: $(node --version)"
echo "npm version: $(npm --version)"

# Install codebuff globally
echo ""
echo "Installing codebuff globally..."
npm install -g codebuff

# Run codebuff to get auth URL
echo ""
echo "=========================================="
echo "Running codebuff to get auth URL..."
echo "=========================================="
codebuff
