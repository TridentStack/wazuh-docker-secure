#!/bin/bash

# Exit on error
set -e

# Configuration
DEFAULT_TARGET_DIR="wazuh-docker/single-node"
TARGET_DIR=""
INTERNAL_USERS_FILE=""

# Function to generate a secure random alphanumeric password
generate_password() {
    local length=$1
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$length"
}

# Generate a password that meets API password requirements (uppercase, lowercase, number, symbol)
generate_api_password() {
    # Start with a base of random alphanumeric characters
    local base=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 10)

    # Ensure we have at least one uppercase, one lowercase, one number and one symbol
    local uppercase="$(tr -dc 'A-Z' </dev/urandom | head -c 1)"
    local lowercase="$(tr -dc 'a-z' </dev/urandom | head -c 1)"
    local number="$(tr -dc '0-9' </dev/urandom | head -c 1)"
    # Use a limited set of symbols that are less likely to cause issues
    local symbol="$(echo '!@#%*+_-' | fold -w1 | shuf | head -1)"

    # Combine and shuffle to make it less predictable
    echo "${base}${uppercase}${lowercase}${number}${symbol}" | fold -w1 | shuf | tr -d '\n'
}

# Check for Wazuh Docker directory
echo "=== Wazuh User Password Reset Tool ==="
echo ""

# First try the default directory
if [ -d "$DEFAULT_TARGET_DIR" ] && [ -f "$DEFAULT_TARGET_DIR/config/wazuh_indexer/internal_users.yml" ]; then
    TARGET_DIR="$DEFAULT_TARGET_DIR"
    INTERNAL_USERS_FILE="${TARGET_DIR}/config/wazuh_indexer/internal_users.yml"
    echo "Found Wazuh installation at: ${TARGET_DIR}"
else
    echo "Default Wazuh directory not found at ${DEFAULT_TARGET_DIR}"
    echo "Please specify the path to your Wazuh Docker installation directory."
    echo "This is typically the directory containing docker-compose.yml"
    echo "(Example: /path/to/wazuh-docker/single-node)"
    echo ""
    
    while true; do
        read -p "Enter Wazuh installation directory: " USER_DIR
        
        # Check if the directory exists
        if [ ! -d "$USER_DIR" ]; then
            echo "Error: Directory does not exist: $USER_DIR"
            continue
        fi
        
        # Check if internal_users.yml exists
        if [ ! -f "$USER_DIR/config/wazuh_indexer/internal_users.yml" ]; then
            echo "Error: Could not find internal_users.yml in $USER_DIR/config/wazuh_indexer/"
            echo "Please enter a valid Wazuh installation directory."
            continue
        fi
        
        # Valid directory found
        TARGET_DIR="$USER_DIR"
        INTERNAL_USERS_FILE="${TARGET_DIR}/config/wazuh_indexer/internal_users.yml"
        echo "Using Wazuh installation at: ${TARGET_DIR}"
        break
    done
fi

# Now that we have a valid TARGET_DIR, make sure internal_users.yml exists
if [ ! -f "$INTERNAL_USERS_FILE" ]; then
    echo "Error: internal_users.yml not found at ${INTERNAL_USERS_FILE}"
    echo "Please ensure Wazuh is properly installed"
    exit 1
fi

# Extract user list from internal_users.yml
echo "Extracting users from ${INTERNAL_USERS_FILE}..."

# Grep for lines ending with a colon (user definitions) but exclude _meta user
USERS=$(grep -E "^[a-zA-Z0-9_-]+:$" "$INTERNAL_USERS_FILE" | grep -v "^_meta:" | sed 's/:$//')

# Check if any users were found
if [ -z "$USERS" ]; then
    echo "Error: No users found in ${INTERNAL_USERS_FILE}"
    exit 1
fi

# Convert user list to an array
readarray -t USER_ARRAY <<< "$USERS"

# Display numbered list of users
echo ""
echo "Available users:"
echo "----------------"
for i in "${!USER_ARRAY[@]}"; do
    echo "$((i+1)). ${USER_ARRAY[$i]}"
done
echo ""

# Prompt for user selection
while true; do
    read -p "Enter the number of the user to reset password (or 'q' to quit): " SELECTION
    
    # Check for quit
    if [[ "$SELECTION" == "q" ]]; then
        echo "Exiting without changes."
        exit 0
    fi
    
    # Validate selection is a number
    if ! [[ "$SELECTION" =~ ^[0-9]+$ ]]; then
        echo "Please enter a valid number or 'q' to quit."
        continue
    fi
    
    # Adjust for zero-based indexing and check if in range
    INDEX=$((SELECTION-1))
    if [ "$INDEX" -lt 0 ] || [ "$INDEX" -ge "${#USER_ARRAY[@]}" ]; then
        echo "Selection out of range. Please choose a number between 1 and ${#USER_ARRAY[@]}."
        continue
    fi
    
    # Valid selection, break out of loop
    SELECTED_USER="${USER_ARRAY[$INDEX]}"
    break
done

echo ""
echo "=== Resetting password for user: ${SELECTED_USER} ==="
echo ""
echo "WARNING: This operation will restart the Wazuh stack, which may cause"
echo "temporary service interruption. All services will be stopped and restarted."
echo ""

# Ask for confirmation before proceeding
while true; do
    read -p "Are you sure you want to proceed with password reset? (y/n): " CONFIRM
    case $CONFIRM in
        [Yy]* ) break;;
        [Nn]* ) echo "Operation cancelled."; exit 0;;
        * ) echo "Please answer y or n.";;
    esac
done

# Stop the Wazuh stack
echo ""
echo "Stopping Wazuh stack..."
(cd "$TARGET_DIR" && docker compose down)

# Generate appropriate password based on user type
if [ "$SELECTED_USER" == "wazuh-wui" ] || [[ "$SELECTED_USER" == *"api"* ]]; then
    NEW_PASSWORD=$(generate_api_password)
    PASSWORD_TYPE="API"
else
    NEW_PASSWORD=$(generate_password 14)
    PASSWORD_TYPE="standard"
fi

echo ""
echo "Generated new ${PASSWORD_TYPE} password: $NEW_PASSWORD"
echo ""

# Generate hash for the new password
echo "Generating password hash..."
PASSWORD_HASH=$(docker run --rm wazuh/wazuh-indexer:4.11.2 bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$NEW_PASSWORD" | grep '^\$2' | head -1)
echo "Generated password hash: $PASSWORD_HASH"

# Update the internal_users.yml file with the new hash
echo "Updating internal_users.yml with new hash..."
if [ -f "$INTERNAL_USERS_FILE" ]; then
    # Create a backup
    cp "$INTERNAL_USERS_FILE" "${INTERNAL_USERS_FILE}.bak"

    # Find the line number of selected user entry
    USER_LINE=$(grep -n "^${SELECTED_USER}:" "$INTERNAL_USERS_FILE" | cut -d: -f1)
    if [ -z "$USER_LINE" ]; then
        echo "Error: Could not find '${SELECTED_USER}:' line in $INTERNAL_USERS_FILE"
        exit 1
    fi

    # The hash should be on the next line
    HASH_LINE=$((USER_LINE + 1))

    # Replace the hash on that specific line
    sed -i "${HASH_LINE}s|hash: .*|hash: \"$PASSWORD_HASH\"|" "$INTERNAL_USERS_FILE"

    # Verify the change was made
    if grep -A 1 "^${SELECTED_USER}:" "$INTERNAL_USERS_FILE" | grep -q "hash: \"$PASSWORD_HASH\""; then
        echo "Successfully updated ${SELECTED_USER} hash in $INTERNAL_USERS_FILE"
    else
        echo "Error: Failed to update ${SELECTED_USER} hash in $INTERNAL_USERS_FILE"
        echo "Current content:"
        grep -A 3 "^${SELECTED_USER}:" "$INTERNAL_USERS_FILE"
        exit 1
    fi
else
    echo "Error: $INTERNAL_USERS_FILE not found."
    exit 1
fi

# Update the docker-compose.yml for specific users
echo "Updating docker-compose.yml if needed..."
if [ -f "${TARGET_DIR}/docker-compose.yml" ]; then
    # Update docker-compose.yml based on user type
    case "$SELECTED_USER" in
        "admin")
            sed -i "s/INDEXER_PASSWORD=.*/INDEXER_PASSWORD=$NEW_PASSWORD/g" "${TARGET_DIR}/docker-compose.yml"
            echo "docker-compose.yml updated with admin password."
            ;;
        "kibanaserver")
            sed -i "s/DASHBOARD_PASSWORD=.*/DASHBOARD_PASSWORD=$NEW_PASSWORD/g" "${TARGET_DIR}/docker-compose.yml"
            echo "docker-compose.yml updated with kibanaserver password."
            ;;
        "wazuh-wui" | *"api"*)
            sed -i "s/API_PASSWORD=.*/API_PASSWORD=$NEW_PASSWORD/g" "${TARGET_DIR}/docker-compose.yml"
            echo "docker-compose.yml updated with API password."
            
            # For API user, also update wazuh.yml
            WAZUH_YML_FILE="${TARGET_DIR}/config/wazuh_dashboard/wazuh.yml"
            if [ -f "$WAZUH_YML_FILE" ]; then
                cp "$WAZUH_YML_FILE" "${WAZUH_YML_FILE}.bak"
                sed -i 's|password: ".*"|password: "'"$NEW_PASSWORD"'"|' "$WAZUH_YML_FILE"
                echo "wazuh.yml updated with API password."
            fi
            ;;
        *)
            echo "No docker-compose.yml changes needed for this user."
            ;;
    esac
else
    echo "Warning: docker-compose.yml not found at ${TARGET_DIR}/docker-compose.yml"
fi

# Start the stack
echo "Starting Wazuh stack..."
(cd "$TARGET_DIR" && docker compose up -d)

# Wait for initialization
echo "Waiting for Wazuh to initialize (2 minutes)..."
sleep 120

# Get container name
INDEXER_CONTAINER=$(docker ps | grep "wazuh.indexer" | awk '{print $NF}')
if [ -z "$INDEXER_CONTAINER" ]; then
    echo "Error: Could not find the Wazuh indexer container."
    exit 1
fi

# Run the security admin script inside the container
echo "Running security admin script inside the container..."
docker exec -i "$INDEXER_CONTAINER" bash << 'EOF'
# Set variables
export INSTALLATION_DIR=/usr/share/wazuh-indexer
CACERT=$INSTALLATION_DIR/certs/root-ca.pem
KEY=$INSTALLATION_DIR/certs/admin-key.pem
CERT=$INSTALLATION_DIR/certs/admin.pem
export JAVA_HOME=/usr/share/wazuh-indexer/jdk

# Run the security admin script
echo "Running securityadmin.sh script..."
bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /usr/share/wazuh-indexer/opensearch-security/ -nhnv -cacert $CACERT -cert $CERT -key $KEY -p 9200 -icl
EOF

# Final message
echo "=== Password reset completed successfully! ==="
echo ""
echo "NEW CREDENTIALS (SAVE THESE SECURELY):"
echo "-------------------------------------------"
echo "Username: $SELECTED_USER"
echo "Password: $NEW_PASSWORD"
echo "-------------------------------------------"
echo ""
# Get primary IP address
PRIMARY_IP=$(hostname -I | awk '{print $1}')
if [ -z "$PRIMARY_IP" ]; then
    # Fallback if hostname -I doesn't work
    PRIMARY_IP=$(ip route get 1 | awk '{print $7}' 2>/dev/null || echo "localhost")
fi

echo "Access the Wazuh dashboard at: https://${PRIMARY_IP}:443"
echo ""
echo "IMPORTANT: Remember to clear your browser site data before attempting to log in!"

exit 0