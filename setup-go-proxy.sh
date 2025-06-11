# File: setup-go-proxy.sh
#!/bin/bash

# Configure Go modules to fetch dependencies directly from GitHub.
# Run this script if you encounter 'Forbidden' errors when downloading modules.
# For corporate environments with a custom mirror, replace 'direct' with the proxy URL.

set -e

if [ -z "$1" ]; then
    echo "Setting GOPROXY=direct"
    go env -w GOPROXY=direct
else
    echo "Setting GOPROXY=$1"
    go env -w GOPROXY=$1
fi

