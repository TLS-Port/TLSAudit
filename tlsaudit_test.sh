#!/bin/bash

setUp() {
    # Source TLSAudit functions
    source ./lib/parser.sh
    source ./lib/checker.sh
    source ./lib/reporter.sh

    # Parse the Nginx configuration file
    parseNginxConfig ./test/nginx_example1.conf

    # Loop through the array and store specific values in selected variables
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

    # Check Nnginx TLS options
    checkNginxTLSOptions "$tls_options"

    # Loop through the array and and store specific values in selected variables
    for element in "${tls_audit_weak[@]}"; do
        if [[ "$element" == "ssl_early_data:on" ]]; then
            audit_weak_ssl_early_data="$element"
        fi
    done

        # Loop through the array and store specific values in selected variables
    for element in "${tls_audit_insecure[@]}"; do
        if [[ "$element" == "ssl_protocols:TLSv1" ]]; then
            audit_insecure_tls1="$element"
        elif [[ "$element" == "ssl_protocols:TLSv1.1" ]]; then
            audit_insecure_tls11="$element"
        elif [[ "$element" == "ssl_protocols:SSLv2" ]]; then
            audit_insecure_SSLv2="$element"
        elif [[ "$element" == "ssl_protocols:SSLv3" ]]; then
            audit_insecure_SSLv3="$element"
        elif [[ "$element" == "ssl_ecdh_curve:secp192r1" ]]; then
            audit_insecure_SECP192R1="$element"
        elif [[ "$element" == "ssl_ecdh_curve:secp224r1" ]]; then
            audit_insecure_SECP224R1="$element"
        elif [[ "$element" == "ssl_ecdh_curve:secp160r1" ]]; then
            audit_insecure_SECP160R1="$element"
        elif [[ "$element" == "ssl_ecdh_curve:secp160k1" ]]; then
            audit_insecure_SECP160K1="$element"
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

testParserProtocolTLSv1() {
    # Test if the parser correctly extracts TLSv1 protocol
    assertEquals "Nginx configuration contains ssl_protocols:TLSv1" "ssl_protocols:TLSv1" "$opt_tls1" 
}

testParserProtocolTLSv11() {
    # Test if the parser correctly extracts TLSv1.1 protocol
    assertEquals "Nginx configuration contains ssl_protocols:TLSv1.1" "ssl_protocols:TLSv1.1" "$opt_tls11" 
}

testParserProtocolTLSv12() {
    # Test if the parser correctly extracts TLSv1.2 protocol
    assertEquals "Nginx configuration contains ssl_protocols:TLSv1.2" "ssl_protocols:TLSv1.2" "$opt_tls12" 
}

testParserCipherHIGH() {
    # Test if the parser correctly extracts HIGH cipher
    assertEquals "Nginx configuration contains ssl_ciphers:HIGH" "ssl_ciphers:HIGH" "$opt_ciphers_high" 
}

testParserCipheraNull() {
    # Test if the parser correctly extracts !aNULL cipher
    assertEquals "Nginx configuration contains ssl_ciphers:!aNULL" "ssl_ciphers:!aNULL" "$opt_ciphers_not_anull" 
}

testParserCipherMD5() {
    # Test if the parser correctly extracts !MD5 cipher
    assertEquals "Nginx configuration contains ssl_ciphers:!MD5" "ssl_ciphers:!MD5" $opt_ciphers_not_md5 
}

testCheckerProtocolSSLv2() {
    # Test if the checker can identify weak or insecure options
    checkNginxTLSOptions "$tls_options"

    assertEquals "SSLv2 option is insecure." "ssl_protocols:SSLv2" "$audit_insecure_SSLv2" 
}

testCheckerProtocolSSLv3() {
    # Test if the checker can identify weak or insecure options
    checkNginxTLSOptions "$tls_options"

    assertEquals "SSLv3 option is insecure." "ssl_protocols:SSLv3" "$audit_insecure_SSLv3" 
}

testCheckerProtocolTLSv1() {
    # Test if the checker can identify weak or insecure options
    checkNginxTLSOptions "$tls_options"

    assertEquals "TLSv1 option is insecure." "ssl_protocols:TLSv1" "$audit_insecure_tls1" 
}

testCheckerProtocolTLSv11() {
    # Test if the checker can identify weak or insecure options
    checkNginxTLSOptions "$tls_options"

    assertEquals "TLSv1.1 option is insecure." "ssl_protocols:TLSv1.1" "$audit_insecure_tls11" 
}

testCheckerSSLEarlyData() {
    # Test if the checker can identify weak or insecure options
    checkNginxTLSOptions "$tls_options"

    assertEquals "SSL Early Data option is weak." "ssl_early_data:on" "$audit_weak_ssl_early_data"
}

testCheckerSECP192R1() {
    # Test if the checker can identify weak or insecure options
    checkNginxTLSOptions "$tls_options"

    assertEquals "secp192r1 option is insecure." "ssl_ecdh_curve:secp192r1" "$audit_insecure_SECP192R1" 
}

testCheckerSECP224R1() {
    # Test if the checker can identify weak or insecure options
    checkNginxTLSOptions "$tls_options"

    assertEquals "secp224r1 option is insecure." "ssl_ecdh_curve:secp224r1" "$audit_insecure_SECP224R1" 
}

testCheckerSECP160R1() {
    # Test if the checker can identify weak or insecure options
    checkNginxTLSOptions "$tls_options"

    assertEquals "secp160r1 option is insecure." "ssl_ecdh_curve:secp160r1" "$audit_insecure_SECP160R1" 
}

testCheckerSECP160K1() {
    # Test if the checker can identify weak or insecure options
    checkNginxTLSOptions "$tls_options"

    assertEquals "secp160K1 option is insecure." "ssl_ecdh_curve:secp160k1" "$audit_insecure_SECP160K1" 
}

. shunit2
