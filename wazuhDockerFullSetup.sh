#!/bin/bash

# Exit on error
set -e

# Configuration
REPO_URL="https://github.com/wazuh/wazuh-docker.git"
BRANCH="v4.11.2"
CLONE_DIR="wazuh-docker"
TARGET_DIR="${CLONE_DIR}/single-node"
DEFAULT_PASSWORD="SecretPassword"  # Default password in Wazuh
DEFAULT_KIBANA_PASSWORD="kibanaserver"  # Default kibanaserver password
DEFAULT_API_PASSWORD="MyS3cr37P450r.*-"  # Default API password

# Users to update passwords for
USERS_TO_UPDATE=(
    "admin"
    "kibanaserver"
    "kibanaro"
    "logstash"
    "readall"
    "snapshotrestore"
)

# Function to generate a secure random alphanumeric password (no special chars)
generate_password() {
    local length=$1
    # Using only alphanumeric characters to avoid shell escaping issues
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$length"
}

# Generate a password that meets API password requirements (uppercase, lowercase, number, symbol)
# Important: Avoids $ and & characters which can cause deployment errors
generate_api_password() {
    # Start with a base of random alphanumeric characters
    local base=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 10)

    # Ensure we have at least one uppercase, one lowercase, one number and one symbol
    local uppercase="$(tr -dc 'A-Z' </dev/urandom | head -c 1)"
    local lowercase="$(tr -dc 'a-z' </dev/urandom | head -c 1)"
    local number="$(tr -dc '0-9' </dev/urandom | head -c 1)"
    # Use a limited set of symbols that are less likely to cause issues (explicitly avoiding $ and &)
    local symbol="$(echo '!@#%*+_-' | fold -w1 | shuf | head -1)"

    # Combine and shuffle to make it less predictable
    echo "${base}${uppercase}${lowercase}${number}${symbol}" | fold -w1 | shuf | tr -d '\n'
}

# Function to clean up any existing Wazuh deployment
cleanup_volumes() {
    echo "Cleaning up any existing Wazuh Docker volumes..."
    # List all volumes related to single-node first
    local volumes=$(docker volume ls -q | grep single-node || true)
    if [ -n "$volumes" ]; then
        # Remove all single-node volumes
        for vol in $volumes; do
            echo "Removing volume: $vol"
            docker volume rm $vol
        done
    else
        echo "No existing Wazuh volumes found."
    fi
}

echo "=== Starting Wazuh setup with custom passwords for all users ==="

# Check requirements
if ! command -v docker &> /dev/null; then
    echo "Error: docker is required but not installed."
    exit 1
fi

if ! docker compose version &> /dev/null; then
    echo "Error: docker compose is required but not installed."
    exit 1
fi

# Clean up any previous deployments
if [ -d "$TARGET_DIR" ]; then
    echo "Stopping any existing Wazuh containers..."
    (cd "$TARGET_DIR" && docker compose down) 2>/dev/null || true
fi

# Clean up volumes
cleanup_volumes

# Clone repository
if [ ! -d "$CLONE_DIR" ]; then
    echo "Cloning Wazuh Docker repository..."
    git clone "$REPO_URL" -b "$BRANCH" "$CLONE_DIR"
else
    echo "Using existing Wazuh Docker repository..."
fi

# Change to target directory
cd "$TARGET_DIR"
echo "Working directory: $(pwd)"

# Make sure the directory exists with proper permissions before generation
echo "Setting up certificate directory..."
mkdir -p config/wazuh_indexer_ssl_certs
chmod 750 config/wazuh_indexer_ssl_certs 2>/dev/null || true

# PHASE 1: Generate certificates
echo "=== PHASE 1: Generating certificates ==="
echo "Generating self-signed certificates..."
docker compose -f generate-indexer-certs.yml run --rm generator

# Fix permissions on certificate directory if needed
if [ ! -r "config/wazuh_indexer_ssl_certs/root-ca.pem" ]; then
    echo "Fixing certificate permissions..."
    sudo chown -R $(id -u):$(id -g) config/wazuh_indexer_ssl_certs 2>/dev/null || true
fi

# Verify certificates exist
echo "Verifying certificates..."
if [ ! -f "config/wazuh_indexer_ssl_certs/root-ca.pem" ]; then
    echo "Error: Certificate file not found. Check permissions or run with sudo."
    exit 1
fi
echo "Certificates generated successfully."

# PHASE 2: Initial stack startup with default credentials
echo "=== PHASE 2: Initial Stack Startup with Default Credentials ==="
echo "Starting Wazuh stack with default credentials..."
docker compose up -d

# Wait for full initialization
echo "Waiting for Wazuh to initialize fully (3 minutes)..."
echo "This initial startup may take several minutes..."
sleep 180  # Allow plenty of time for initial setup

# Verify the stack is running
if ! docker ps | grep -q "wazuh.indexer"; then
    echo "Error: Wazuh indexer is not running. Initial setup failed."
    exit 1
fi
echo "Initial stack startup completed successfully."

######################
# ALL USERS PASSWORD CHANGE
######################

# PHASE 3: Stop the stack for password changes
echo "=== PHASE 3: Stopping Stack for All Users Password Changes ==="
echo "Stopping Wazuh stack..."
docker compose down

# PHASE 4: Generate passwords and hashes for all users (WITH STACK DOWN)
echo "=== PHASE 4: Generating password hashes for all users ==="

# Define internal_users.yml file path
INTERNAL_USERS_FILE="config/wazuh_indexer/internal_users.yml"

# Create a backup of internal_users.yml
if [ -f "$INTERNAL_USERS_FILE" ]; then
    cp "$INTERNAL_USERS_FILE" "${INTERNAL_USERS_FILE}.bak"
else
    echo "Error: $INTERNAL_USERS_FILE not found."
    exit 1
fi

# Create a backup of docker-compose.yml
if [ -f "docker-compose.yml" ]; then
    cp docker-compose.yml docker-compose.yml.bak
else
    echo "Error: docker-compose.yml not found."
    exit 1
fi

# Dictionary to store new passwords
declare -A USER_PASSWORDS

# Generate passwords and update hashes for all users
for USER in "${USERS_TO_UPDATE[@]}"; do
    echo "=== Processing user: $USER ==="
    
    # Generate appropriate password based on user type
    if [ "$USER" == "wazuh-wui" ] || [[ "$USER" == *"api"* ]]; then
        NEW_PASSWORD=$(generate_api_password)
        PASSWORD_TYPE="API"
    else
        NEW_PASSWORD=$(generate_password 14)
        PASSWORD_TYPE="standard"
    fi
    
    # Store password for later
    USER_PASSWORDS[$USER]=$NEW_PASSWORD
    
    echo "Generated new ${PASSWORD_TYPE} password for $USER: $NEW_PASSWORD"
    
    # Generate hash for the password
    echo "Generating password hash for $USER..."
    PASSWORD_HASH=$(docker run --rm wazuh/wazuh-indexer:4.11.2 bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "$NEW_PASSWORD" | grep '^\$2' | head -1)
    echo "Generated password hash for $USER: $PASSWORD_HASH"
    
    # Update the hash in internal_users.yml
    echo "Updating internal_users.yml with $USER hash..."
    USER_LINE=$(grep -n "^$USER:" "$INTERNAL_USERS_FILE" | cut -d: -f1)
    if [ -z "$USER_LINE" ]; then
        echo "Warning: Could not find '$USER:' line in $INTERNAL_USERS_FILE - skipping this user"
        continue
    fi
    
    # The hash should be on the next line
    HASH_LINE=$((USER_LINE + 1))
    
    # Replace the hash on that specific line
    sed -i "${HASH_LINE}s|hash: .*|hash: \"$PASSWORD_HASH\"|" "$INTERNAL_USERS_FILE"
    
    # Verify the change was made
    if grep -A 1 "^$USER:" "$INTERNAL_USERS_FILE" | grep -q "hash: \"$PASSWORD_HASH\""; then
        echo "Successfully updated $USER hash in $INTERNAL_USERS_FILE"
    else
        echo "Error: Failed to update $USER hash in $INTERNAL_USERS_FILE"
        echo "Current content:"
        grep -A 3 "^$USER:" "$INTERNAL_USERS_FILE"
        exit 1
    fi
    
    echo "Password for $USER updated successfully."
    echo ""
done

# Update the docker-compose.yml file with the new passwords for special users
echo "Updating docker-compose.yml with new passwords..."

# Update admin password
if [ -n "${USER_PASSWORDS[admin]}" ]; then
    sed -i "s/INDEXER_PASSWORD=.*/INDEXER_PASSWORD=${USER_PASSWORDS[admin]}/g" docker-compose.yml
    echo "docker-compose.yml updated with admin password."
fi

# Update kibanaserver password
if [ -n "${USER_PASSWORDS[kibanaserver]}" ]; then
    sed -i "s/DASHBOARD_PASSWORD=.*/DASHBOARD_PASSWORD=${USER_PASSWORDS[kibanaserver]}/g" docker-compose.yml
    echo "docker-compose.yml updated with kibanaserver password."
fi

# Generate and update API user password separately since it's not in the user list above
API_PASSWORD=$(generate_api_password)
echo ""
echo "Generated new API password: $API_PASSWORD"
echo ""

# Update the wazuh.yml file with the new API password
echo "Updating wazuh.yml with new API password..."
WAZUH_YML_FILE="config/wazuh_dashboard/wazuh.yml"
if [ -f "$WAZUH_YML_FILE" ]; then
    # Create a backup
    cp "$WAZUH_YML_FILE" "${WAZUH_YML_FILE}.bak"

    # Replace the password line - being careful with quotes and formatting
    sed -i 's|password: ".*"|password: "'"$API_PASSWORD"'"|' "$WAZUH_YML_FILE"

    # Verify the change was made
    if grep -q "[[:space:]]*password:[[:space:]]*\"$API_PASSWORD\"" "$WAZUH_YML_FILE"; then
        echo "Successfully updated API password in $WAZUH_YML_FILE"
    else
        # Even if verification fails, check if password appears anywhere in the file
        if grep -q "$API_PASSWORD" "$WAZUH_YML_FILE"; then
            echo "Password found in file but pattern didn't match exactly. Continuing anyway."
        else
            echo "Error: Failed to update API password in $WAZUH_YML_FILE"
            echo "Current content:"
            grep -A 1 "password:" "$WAZUH_YML_FILE"
            exit 1
        fi
    fi
    
    # Update API_PASSWORD in docker-compose.yml
    sed -i "s/API_PASSWORD=.*/API_PASSWORD=$API_PASSWORD/g" docker-compose.yml
    echo "docker-compose.yml updated with API password."
else
    echo "Error: $WAZUH_YML_FILE not found."
    exit 1
fi

# PHASE 5: Start the stack with the new credentials
echo "=== PHASE 5: Starting Wazuh with All New Passwords ==="

# Start the stack
echo "Starting Wazuh stack..."
docker compose up -d

# Wait for initialization
echo "Waiting for Wazuh to initialize (2 minutes)..."
sleep 120

# Get container name
INDEXER_CONTAINER=$(docker ps | grep "wazuh.indexer" | awk '{print $NF}')
if [ -z "$INDEXER_CONTAINER" ]; then
    echo "Error: Could not find the Wazuh indexer container."
    exit 1
fi

# PHASE 6: Run the security admin script inside the container
echo "=== PHASE 6: Applying Security Settings ==="

# Execute the security admin script
echo "Running security admin script inside the container..."
docker exec -i "$INDEXER_CONTAINER" bash << 'EOF'
# Set variables
export INSTALLATION_DIR=/usr/share/wazuh-indexer
CACERT=$INSTALLATION_DIR/certs/root-ca.pem
KEY=$INSTALLATION_DIR/certs/admin-key.pem
CERT=$INSTALLATION_DIR/certs/admin.pem
export JAVA_HOME=/usr/share/wazuh-indexer/jdk

# Run the security admin script
echo "Running securityadmin.sh script for all security config updates..."
bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /usr/share/wazuh-indexer/opensearch-security/ -nhnv -cacert $CACERT -cert $CERT -key $KEY -p 9200 -icl
EOF

# Final message
echo "=== Wazuh setup completed successfully! ==="
echo ""
echo "GENERATED CREDENTIALS (SAVE THESE SECURELY):"
echo "-------------------------------------------"

# Print all user passwords
for USER in "${!USER_PASSWORDS[@]}"; do
    echo "Username: $USER"
    echo "Password: ${USER_PASSWORDS[$USER]}"
    echo ""
done

# Print API password
echo "API username: wazuh-wui"
echo "API password: $API_PASSWORD"
echo "-------------------------------------------"
# Get primary IP address
PRIMARY_IP=$(hostname -I | awk '{print $1}')
if [ -z "$PRIMARY_IP" ]; then
    # Fallback if hostname -I doesn't work
    PRIMARY_IP=$(ip route get 1 | awk '{print $7}' 2>/dev/null || echo "localhost")
fi

echo ""
echo "Access the Wazuh dashboard at: https://${PRIMARY_IP}:443"
echo ""
echo "IMPORTANT: Remember to clear your browser site data before attempting to log in!"

exit 0