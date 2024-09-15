#!/bin/bash

# Check if an argument is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <nginx_config_file>"
    exit 1
fi

# Read the Nginx configuration file from the command line argument
nginx_config_file="$1"

source ./lib/parser.sh
source ./lib/checker.sh
source ./lib/reporter.sh

# Runs TLS audit with the provided Nginx configuration file
parseNginxConfig "$nginx_config_file"
checkNginxTLSOptions "$tls_options"
reportWeakTLSOptions
