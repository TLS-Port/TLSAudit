#!/bin/bash

setUp() {
    # Set up the test environment
    source ./lib/parser.sh

    # Call the function
    parseNginxConfig ./test/nginx_example1.conf

    # Loop through the array and print each element on a new line
    for element in "${tls_options[@]}"; do
        if [[ "$element" == "ssl_protocols:TLSv1" ]]; then
            opt_tls1="$element"
        elif [[ "$element" == "ssl_protocols:TLSv1.1" ]]; then
            opt_tls11="$element"
        elif [[ "$element" == "ssl_protocols:TLSv1.2" ]]; then
            opt_tls12="$element"
        elif [[ "$element" == "ssl_ciphers:HIGH" ]]; then
            opt_ciphers_high="$element"
        elif [[ "$element" == "ssl_ciphers:!aNULL" ]]; then
            opt_ciphers_not_anull="$element"
        elif [[ "$element" == "ssl_ciphers:!MD5" ]]; then
            opt_ciphers_not_md5="$element"
        fi
    done
}

tearDown() {
    # Tear down the test environment
    tls_options=()
    element=""
}

testParserProtocolTLSv1() {
    # Test if the parser correctly extracts TLSv1 protocol
    assertEquals "Nginx configuration contains ssl_protocols:TLSv1" "$opt_tls1" "ssl_protocols:TLSv1"
}

testParserProtocolTLSv11() {
    # Test if the parser correctly extracts TLSv1.1 protocol
    assertEquals "Nginx configuration contains ssl_protocols:TLSv1.1" "$opt_tls11" "ssl_protocols:TLSv1.1"
}

testParserProtocolTLSv12() {
    # Test if the parser correctly extracts TLSv1.2 protocol
    assertEquals "Nginx configuration contains ssl_protocols:TLSv1.2" "$opt_tls12" "ssl_protocols:TLSv1.2"
}

testParserCipherHIGH() {
    # Test if the parser correctly extracts HIGH cipher
    assertEquals "Nginx configuration contains ssl_ciphers:HIGH" "$opt_ciphers_high" "ssl_ciphers:HIGH"
}

testParserCipheraNull() {
    # Test if the parser correctly extracts !aNULL cipher
    assertEquals "Nginx configuration contains ssl_ciphers:!aNULL" "$opt_ciphers_not_anull" "ssl_ciphers:!aNULL"
}

testParserCipherMD5() {
    # Test if the parser correctly extracts !MD5 cipher
    assertEquals "Nginx configuration contains ssl_ciphers:!MD5" $opt_ciphers_not_md5 "ssl_ciphers:!MD5"
}

# Checker: take L and dictionary D as input, output list R containing configuration options which are either weak or insecure

#testChecker() {
#    # Test if the checker can identify weak or insecure options
#    fail "Test not implemented"
#}

# Reporter: take R as input and generate a simple command line report (if needed, different report formats can be added later)

#testReporter() {
#    # Test if the reporter can generate a report
#    fail "Test not implemented"
#}

. shunit2
