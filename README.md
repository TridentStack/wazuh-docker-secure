# wazuh-docker-secure

Secure Wazuh deployment automation for Docker with enhanced password management, certificate generation, and security hardening. These scripts automate full setup and credential management, eliminating default passwords and implementing security best practices.

## Installation Scripts

### Wazuh Docker Full Setup

This script performs a complete Wazuh installation with Docker:
- Clones the official Wazuh Docker repository
- Generates SSL certificates
- Replaces all default passwords with secure random passwords
- Sets up the complete stack with security hardening
- Displays all generated credentials for safekeeping

```bash
sudo bash -c "$(wget -qLO - https://github.com/TridentStack/wazuh-docker-secure/raw/refs/heads/main/wazuhDockerFullSetup.sh)"
```

### Wazuh Password Reset

This script allows you to reset passwords for any Wazuh user:
- Lists all available users from your current Wazuh installation
- Generates secure random passwords appropriate for each user type
- Updates configuration files and applies changes
- Restarts services to apply the new credentials

```bash
sudo bash -c "$(wget -qLO - https://github.com/TridentStack/wazuh-docker-secure/raw/refs/heads/main/wazuhResetPassword.sh)"
```

## Requirements

- Docker with Docker Compose V2 installed (scripts use `docker compose`, not `docker-compose`)
- Git installed
- Sufficient permissions (sudo access)
- Outbound internet access for downloading the Wazuh repository

These scripts have been tested on Ubuntu 24.04 using the official Docker installation method from [https://docs.docker.com/engine/install/ubuntu/](https://docs.docker.com/engine/install/ubuntu/)

## Important Caution

⚠️ **Before running these scripts on an existing Wazuh deployment, ensure you have created proper backups of your configuration and data.** While these scripts are designed to be safe and include their own backup mechanisms for configuration files, it's always best practice to have a complete backup of your environment before making system-wide changes.

## Security Notes

- Standard user passwords consist of alphanumeric characters only (14 characters), as Wazuh has compatibility issues with special characters for these users
- Only API passwords include special characters, following Wazuh's specific API requirements
- Password length is limited to 14 characters as Wazuh has issues with longer passwords
- Scripts create backups of critical configuration files before modification
- All credentials are displayed at the end of execution for secure storage by the administrator