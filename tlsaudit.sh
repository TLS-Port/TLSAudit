#!/bin/bash

source ./lib/parser.sh
source ./lib/checker.sh
source ./lib/reporter.sh

# Call the function
parseNginxConfig ./test/nginx_example1.conf

# Print the array
#echo "Array elements: ${tls_options[@]}"
# Loop through the array and print each element on a new line
for element in "${tls_options[@]}"; do
    echo "$element"
done
