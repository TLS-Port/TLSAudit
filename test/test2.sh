#!/bin/bash

setUp() {
    # Source TLSAudit functions
    source ../lib/parser.sh
    source ../lib/checker.sh
    source ../lib/reporter.sh

    # Parse the Nginx configuration file
    parseNginxConfig ./nginx2.conf

    # Loop through the array and store specific values in selected variables
    for element in "${tls_options[@]}"; do
        if [[ "$element" == "ssl_ciphers:MEDIUM" ]]; then
            opt_ciphers_medium="$element"
        fi
    done

    # Test if the checker can identify MEDIUM ciphers as weak option
    checkNginxTLSOptions "$tls_options"

    # Loop through the array and store specific values in selected variables
    for element in "${tls_audit_weak[@]}"; do
        if [[ "$element" == "ssl_ciphers:MEDIUM" ]]; then
            audit_weak_ciphers_medium="$element"
        fi
    done
}

tearDown() {
    # Tear down the test environment
    tls_options=()
    tls_audit_weak=()
    tls_audit_insecure=()
    element=""
}

testParserCipherMEDIUM() {
    # Test if the parser correctly extracts MEDIUM ciphers
    assertEquals "Nginx configuration contains ssl_ciphers:MEDIUM" "ssl_ciphers:MEDIUM" "$opt_ciphers_medium" 
}

testCheckerCipherMEDIUM() {
    assertEquals "MEDIUM ciphers option is weak." "ssl_ciphers:MEDIUM" "$audit_weak_ciphers_medium" 
}

. shunit2
