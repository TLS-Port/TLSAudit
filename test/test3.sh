#!/bin/bash

setUp() {
    # Source TLSAudit functions
    source ../lib/parser.sh
    source ../lib/checker.sh
    source ../lib/reporter.sh

    # Parse the Nginx configuration file
    parseNginxConfig ./nginx3.conf

    # Loop through the array and store specific values in selected variables
    for element in "${tls_options[@]}"; do
        if [[ "$element" == "ssl_ciphers:NULL" ]]; then
            opt_ciphers_null="$element"
        elif [[ "$element" == "ssl_ciphers:eNULL" ]]; then
            opt_ciphers_enull="$element"
        fi
    done

    # Test if the checker can identify MEDIUM ciphers as insecure option
    checkNginxTLSOptions "$tls_options"

    # Loop through the array and store specific values in selected variables
    for element in "${tls_audit_insecure[@]}"; do
        if [[ "$element" == "ssl_ciphers:NULL" ]]; then
            audit_insecure_ciphers_null="$element"
        elif [[ "$element" == "ssl_ciphers:eNULL" ]]; then
            audit_insecure_ciphers_enull="$element"
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

testParserCipherNULL() {
    # Test if the parser correctly extracts NULL ciphers
    assertEquals "Nginx configuration contains ssl_ciphers:NULL" "ssl_ciphers:NULL" "$opt_ciphers_null" 
}

testParserCiphereNULL() {
    # Test if the parser correctly extracts eNULL ciphers
    assertEquals "Nginx configuration contains ssl_ciphers:eNULL" "ssl_ciphers:eNULL" "$opt_ciphers_enull" 
}

testCheckerCipherNULL() {
    # Test if the checker can identify NULL ciphers as insecure option
    assertEquals "MEDIUM ciphers option is insecure." "ssl_ciphers:NULL" "$audit_insecure_ciphers_null" 
}

testCheckerCiphereNULL() {
    # Test if the checker can identify eNULL ciphers as insecure option
    assertEquals "MEDIUM ciphers option is insecure." "ssl_ciphers:eNULL" "$audit_insecure_ciphers_enull" 
}

. shunit2
