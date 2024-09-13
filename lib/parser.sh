### TLSAudit parser code
###
### Reads the Nginx configuration file and extracts TLS configuration options

# Declare a global array to store TLS-relevant configuration options
tls_options=()

parseNginxConfig() {
    # Check if a file name was provided
    if [ "$#" -ne 1 ]; then
        echo "Usage: $0 <path/to/nginx_config_file>"
        exit 1
    fi

    # Input Nginx config file
    config_file="$1"

    # Check if the file exists
    if [ ! -f "$config_file" ]; then
        echo "Error: File $config_file not found!"
        exit 1
    fi

    # Declare an array to hold the TLS-relevant configuration options
    tls_options=()


    # Use grep to get the lines and read them into the array
    while IFS= read -r line; do
        # Step 1: Remove leading/trailing spaces, remove the semicolon at the end of the line
        #echo "$line"
        cleaned_string=$(echo "$line" | sed 's/^[[:space:]]*//g;s/[[:space:]]*$//g;s/:/ /g;s/;$//g;')

        #echo "Cleaned string: $cleaned_string"

        # Split the string into an array
        IFS=' ' read -r -a array <<< "$cleaned_string"

        # Initialize an empty array to hold the results
        result_array=()

        # Iterate over the array starting from the second element
        for (( i=1; i<${#array[@]}; i++ )); do
            result_array+=("${array[0]}:${array[i]}")
        done

        # Print the resulting array
        for element in "${result_array[@]}"; do
            #echo "New element: $element"
            # Step 3: Store the resulting string in the array
            tls_options+=("$element")
        done

    done < <(grep -E "^\s*(ssl_certificate|ssl_certificate_key|ssl_protocols|ssl_ciphers|ssl_prefer_server_ciphers|ssl_session_cache|ssl_session_timeout|ssl_trusted_certificate|ssl_stapling|ssl_stapling_verify|ssl_dhparam)\s+" "$config_file")
}
