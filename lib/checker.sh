### TLSAudit checker code
###
### Takes parser's output and TLSAudit dictionary as inputs, and outputs a list containing TLS configuration options which are either weak or insecure

# Declare a global array to store weak TLS options
tls_audit_weak=()

# Declare a global array to store insecure TLS options
tls_audit_insecure=()

# Declare a regular array to simulate an associative array
tls_dict=()

# Function to set a key-value pair in the simulated associative array
set_dict() {
    local key="$1"
    local value="$2"
    tls_dict+=("$key#$value")
}

# Function to get a value from the simulated associative array
get_dict() {
    local key="$1"
    for pair in "${tls_dict[@]}"; do
        IFS="#" read -r k v <<< "$pair"
        if [[ "$k" == "$key" ]]; then
            echo "$v"
            return
        fi
    done
}

# Populate the dictionary
set_dict "ssl_protocols:SSLv2" "insecure"
set_dict "ssl_protocols:SSLv3" "insecure"
set_dict "ssl_protocols:TLSv1" "insecure"
set_dict "ssl_protocols:TLSv1.1" "insecure"
set_dict "ssl_early_data:on" "weak"
set_dict "ssl_ciphers:aNULL" "insecure"
set_dict "ssl_ciphers:MD5" "insecure"
set_dict "ssl_ciphers:EXPORT56" "insecure"
set_dict "ssl_ciphers:RC4+RSA" "insecure"
set_dict "ssl_ciphers:DES" "insecure"
set_dict "ssl_ciphers:3DES" "insecure"
set_dict "ssl_ecdh_curve:secp192r1" "insecure"
set_dict "ssl_ecdh_curve:secp224r1" "insecure"
set_dict "ssl_ecdh_curve:secp160r1" "insecure"
set_dict "ssl_ecdh_curve:secp160k1" "insecure"


search_dict() {
    # Function to search for a key in the dictionary
    local key="$1"
    get_dict "$key"
}

checkNginxTLSOptions() {
    # iterate over the tls_options array, call the search_dict() function for each element in tls_options, and add the result to tls_audit_weak if search_dict() returns "weak" or to tls_audit_insecure if it returns "insecure"
    for element in "${tls_options[@]}"; do
        result=$(search_dict "$element")
        if [[ "$result" == "weak" ]]; then
            tls_audit_weak+=("$element")
        elif [[ "$result" == "insecure" ]]; then
            tls_audit_insecure+=("$element")
        fi
    done
}