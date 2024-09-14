### TLSAudit reporter code
###
### Takes checker's output and generates a simple command line report

reportWeakTLSOptions() {
    # Iterate through the tls_audit_weak array and print the weak TLS options
    echo "Weak TLS options:"
    for element in "${tls_audit_weak[@]}"; do
        echo "    $element"
    done
}

reportInsecureTLSOptions() {
    # Iterate through the tls_audit_insecure array and print the insecure TLS options
    echo "Insecure TLS options:"
    for element in "${tls_audit_insecure[@]}"; do
        echo "    $element"
    done
}