#!/bin/bash

# Load configuration
source /var/ossec/active-response/bin/mikrotik-config.sh

# Execute the Go binary with all arguments
/var/ossec/active-response/bin/mikrotik-block "$@"
