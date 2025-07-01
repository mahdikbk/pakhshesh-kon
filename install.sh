#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# ASCII Art for PAKHSHESH KON
LOGO=$(cat << 'EOF'
    ___          _      _            _                   _         _   _               
   (  _`\       ( )    ( )          ( )                 ( )       ( ) ( )              
   | |_) )  _ _ | |/') | |__    ___ | |__     __    ___ | |__     | |/'/'   _     ___  
   | ,__/'/'_` )| , <  |  _ `\/',__)|  _ `\ /'__`\/',__)|  _ `\   | , <   /'_`\ /' _ `\
   | |   ( (_| || |\`\ | | | |\__, \| | | |(  ___/\__, \| | | |   | |\`\ ( (_) )| ( ) |
   (_)   `\__,_)(_) (_)(_) (_)(____/(_) (_)`\____)(____/(_) (_)   (_) (_)`\___/'(_) (_)
EOF
)

# Powered By text
POWERED_BY="Powered By MahdiKBK"

# Animation function
animate_logo() {
    clear
    echo -e "${CYAN}"
    for ((i=0; i<${#LOGO}; i++)); do
        printf "${LOGO:$i:1}"
        sleep 0.005
    done
    echo -e "${NC}"
    sleep 1
    for color in RED GREEN YELLOW BLUE CYAN; do
        clear
        echo -e "${!color}${LOGO}${NC}"
        echo -e "${MAGENTA}${POWERED_BY}${NC}"
        sleep 0.2
    done
    clear
    echo -e "${GREEN}${LOGO}${NC}"
    # Gradient effect for Powered By
    for ((i=0; i<${#POWERED_BY}; i++)); do
        printf "\033[38;5;$((i*10+160))m${POWERED_BY:$i:1}"
    done
    echo -e "${NC}"
    sleep 1
}

# Generate random string
generate_random_string() {
    openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 16
}

# Detect server country
detect_country() {
    COUNTRY=$(curl -s http://ip-api.com/json | jq -r '.country')
    if [[ -z "$COUNTRY" || "$COUNTRY" == "null" ]]; then
        COUNTRY="Unknown"
    fi
    echo "$COUNTRY"
}

# Check domain resolves to server IP
check_domain() {
    DOMAIN=$1
    SERVER_IP=$(curl -s ifconfig.me)
    RESOLVED_IP=$(dig +short $DOMAIN | tail -n 1)
    if [[ "$RESOLVED_IP" == "$SERVER_IP" ]]; then
        return 0
    else
        return 1
    fi
}

# Main menu
animate_logo
echo -e "${YELLOW}Welcome to Pakhshesh Kon!${NC}"
SERVER_COUNTRY=$(detect_country)
echo -e "${CYAN}Detected server location: $SERVER_COUNTRY${NC}"
echo -e "${CYAN}Choose an option:${NC}"
echo -e "1) Install Pakhshesh Kon"
echo -e "2) Uninstall Pakhshesh Kon"
echo -e "3) Exit"
read -p "Enter your choice (1-3): " choice

if [[ "$choice" == "2" ]]; then
    echo -e "${RED}Uninstalling Pakhshesh Kon...${NC}"
    systemctl stop apache2 mariadb v2ray pakhsheshkon-monitor 2>/dev/null
    systemctl disable apache2 mariadb v2ray pakhsheshkon-monitor 2>/dev/null
    rm -rf /var/www/html/* /etc/pakhsheshkon /usr/local/etc/v2ray /usr/local/bin/monitor.sh
    rm -f /etc/systemd/system/pakhsheshkon-monitor.service
    rm -f /etc/apache2/sites-available/pakhsheshkon.conf
    DB_NAME=$(mysql -e "SHOW DATABASES LIKE 'pk_%'" | grep pk_ || echo "")
    if [[ -n "$DB_NAME" ]]; then
        mysql -e "DROP DATABASE $DB_NAME;"
    fi
    apt purge -y apache2 php php-mysql mariadb-server unzip curl libapache2-mod-php composer v2ray vnstat certbot python3-certbot-apache
    apt autoremove -y
    ufw reset --force
    ufw enable
    echo -e "${GREEN}Pakhshesh Kon completely uninstalled! Server is now clean.${NC}"
    exit 0
elif [[ "$choice" != "1" ]]; then
    echo -e "${YELLOW}Exiting...${NC}"
    exit 0
fi

# Server type selection
echo -e "${YELLOW}Select server type:${NC}"
echo -e "1) Iran"
echo -e "2) Abroad"
read -p "Enter your choice (1-2): " server_type

if [[ "$server_type" == "1" ]]; then
    server_location="iran"
elif [[ "$server_type" == "2" ]]; then
    server_location="abroad"
else
    echo -e "${RED}Invalid choice! Please enter 1 or 2.${NC}"
    exit 1
fi

# Update system
echo -e "${YELLOW}Updating system...${NC}"
apt update && apt upgrade -y

if [[ "$server_location" == "iran" ]]; then
    # Install dependencies
    echo -e "${YELLOW}Installing Apache, PHP, MariaDB, Certbot, and dependencies...${NC}"
    apt install -y apache2 php php-mysql mariadb-server unzip curl libapache2-mod-php composer certbot python3-certbot-apache jq

    # Start and enable services
    systemctl enable apache2 mariadb
    systemctl start apache2 mariadb

    # Secure MariaDB
    echo -e "${YELLOW}Securing MariaDB...${NC}"
    mysql_secure_installation <<EOF

y
y
y
y
y
EOF

    # Create random database credentials
    echo -e "${YELLOW}Setting up database...${NC}"
    DB_NAME="pk_$(generate_random_string)"
    DB_USER="pkuser_$(generate_random_string)"
    DB_PASS=$(generate_random_string)
    mysql -e "CREATE DATABASE $DB_NAME;"
    mysql -e "CREATE USER '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';"
    mysql -e "GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';"
    mysql -e "FLUSH PRIVILEGES;"

    # Get admin credentials
    echo -e "${YELLOW}Enter admin username for panel:${NC}"
    read -p "Username: " admin_user
    echo -e "${YELLOW}Enter admin password:${NC}"
    read -s -p "Password: " admin_pass
    echo

    # Get domain and base URL
    echo -e "${YELLOW}Enter domain for panel (e.g., example.com or panel.example.com):${NC}"
    read -p "Domain: " domain
    echo -e "${YELLOW}Enter base URL path (e.g., xxx for domain.com/xxx, leave empty for root):${NC}"
    read -p "Base URL path: " base_url
    if [[ -z "$base_url" ]]; then
        base_url=""
        install_path="/var/www/html"
    else
        install_path="/var/www/html/$base_url"
        mkdir -p "$install_path"
    fi

    # Check domain resolution
    echo -e "${YELLOW}Checking domain resolution...${NC}"
    if check_domain "$domain"; then
        echo -e "${GREEN}Domain $domain resolves to this server.${NC}"
    else
        echo -e "${RED}Domain $domain does not resolve to this server's IP.${NC}"
        echo -e "${YELLOW}If using Cloudflare, ensure Proxy (orange cloud) is OFF and DNS is set to this server's IP.${NC}"
        read -p "Continue anyway? (y/n): " continue_domain
        if [[ "$continue_domain" != "y" ]]; then
            echo -e "${RED}Installation aborted.${NC}"
            exit 1
        fi
    fi

    # Setup SSL
    echo -e "${YELLOW}Setting up SSL for $domain...${NC}"
    if certbot --apache -d "$domain" --non-interactive --agree-tos --email admin@$domain; then
        echo -e "${GREEN}SSL certificate installed successfully.${NC}"
        protocol="https"
    else
        echo -e "${RED}Failed to install SSL. Proceeding without SSL.${NC}"
        protocol="http"
    fi

    # Download and extract panel
    echo -e "${YELLOW}Downloading panel...${NC}"
    curl -L -o panel.zip https://github.com/mahdikbk/pakhshesh-kon/releases/latest/download/panel.zip
    unzip panel.zip -d /var/www/html/panel_tmp
    mv /var/www/html/panel_tmp/panel/* "$install_path/"
    rm -rf /var/www/html/panel_tmp panel.zip

    # Install composer dependencies
    composer require endroid/qr-code -d "$install_path"

    # Configure database
    cat > "$install_path/includes/config.php" <<EOL
<?php
define('DB_HOST', 'localhost');
define('DB_NAME', '$DB_NAME');
define('DB_USER', '$DB_USER');
define('DB_PASS', '$DB_PASS');
define('SECRET_KEY', '$(generate_random_string)');
define('BASE_URL', '$base_url');
?>
EOL

    # Create database tables
    mysql -u$DB_USER -p$DB_PASS $DB_NAME <<EOF
CREATE TABLE admins (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(255) NOT NULL
);
INSERT INTO admins (username, password) VALUES ('$admin_user', '$(php -r "echo password_hash('$admin_pass', PASSWORD_BCRYPT);")');
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    uuid VARCHAR(36) NOT NULL,
    server_group_id INT NOT NULL,
    traffic_limit BIGINT NOT NULL,
    traffic_used BIGINT DEFAULT 0,
    connection_limit INT NOT NULL,
    expiry_date DATE NOT NULL,
    qr_path VARCHAR(255),
    link TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE server_groups (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE servers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    group_id INT NOT NULL,
    ip VARCHAR(15) NOT NULL,
    port INT NOT NULL,
    name VARCHAR(50),
    unique_code VARCHAR(64) NOT NULL,
    status ENUM('active', 'inactive') DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE monitoring (
    id INT AUTO_INCREMENT PRIMARY KEY,
    server_id INT NOT NULL,
    active_users INT,
    bandwidth VARCHAR(50),
    ping INT,
    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
EOF

    # Set permissions
    chown -R www-data:www-data "$install_path"
    chmod -R 755 "$install_path"

    # Configure Apache
    cat > /etc/apache2/sites-available/pakhsheshkon.conf <<EOL
<VirtualHost *:80>
    ServerName $domain
    DocumentRoot $install_path
    <Directory $install_path>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    ErrorLog \${APACHE_LOG_DIR}/pakhsheshkon-error.log
    CustomLog \${APACHE_LOG_DIR}/pakhsheshkon-access.log combined
</VirtualHost>
<VirtualHost *:443>
    ServerName $domain
    DocumentRoot $install_path
    <Directory $install_path>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/$domain/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/$domain/privkey.pem
    ErrorLog \${APACHE_LOG_DIR}/pakhsheshkon-ssl-error.log
    CustomLog \${APACHE_LOG_DIR}/pakhsheshkon-ssl-access.log combined
</VirtualHost>
EOL

    a2ensite pakhsheshkon.conf
    a2enmod rewrite ssl
    systemctl restart apache2

    echo -e "${GREEN}Installation completed! Access panel at $protocol://$domain${base_url:+/$base_url}/${NC}"
    echo -e "${GREEN}Admin Username: $admin_user${NC}"
    echo -e "${GREEN}Admin Password: [Your chosen password]${NC}"

else
    # Install dependencies for abroad server
    echo -e "${YELLOW}Installing V2Ray and dependencies...${NC}"
    apt install -y curl unzip ufw vnstat jq

    # Get server name
    echo -e "${YELLOW}Enter a name for this server (e.g., Finland-1):${NC}"
    read -p "Server Name: " server_name

    # Generate random port
    V2RAY_PORT=$((RANDOM % 10000 + 10000))
    echo -e "${YELLOW}Generated V2Ray port: $V2RAY_PORT${NC}"

    # Install V2Ray
    bash <(curl -L https://github.com/v2fly/v2ray-core/releases/latest/download/install-release.sh)

    # Generate encrypted server code
    SERVER_IP=$(curl -s ifconfig.me)
    SECRET_KEY=$(generate_random_string)
    SERVER_DATA=$(echo -n "$SERVER_IP|$V2RAY_PORT|$server_name")
    UNIQUE_CODE=$(echo -n "$SERVER_DATA" | openssl dgst -sha256 -hmac "$SECRET_KEY" | head -c 64)
    echo -e "${GREEN}Encrypted Server Code: $UNIQUE_CODE${NC}"

    # Save server config
    mkdir -p /etc/pakhsheshkon
    cat > /etc/pakhsheshkon/server.conf <<EOL
SERVER_IP=$SERVER_IP
V2RAY_PORT=$V2RAY_PORT
SERVER_NAME=$server_name
SECRET_KEY=$SECRET_KEY
UNIQUE_CODE=$UNIQUE_CODE
EOL
    chmod 600 /etc/pakhsheshkon/server.conf

    # Configure V2Ray
    cat > /usr/local/etc/v2ray/config.json <<EOL
{
  "inbounds": [
    {
      "port": $V2RAY_PORT,
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls"
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom"
    }
  ]
}
EOL

    # Configure firewall
    ufw allow 80,443,$V2RAY_PORT/tcp
    ufw --force enable

    # Download and setup monitoring script
    curl -L -o /usr/local/bin/monitor.sh https://raw.githubusercontent.com/mahdikbk/pakhshesh-kon/main/scripts/monitor.sh
    chmod +x /usr/local/bin/monitor.sh

    # Setup systemd service for monitoring
    cat > /etc/systemd/system/pakhsheshkon-monitor.service <<EOL
[Unit]
Description=Pakhshesh Kon Monitoring Service
After=network.target

[Service]
ExecStart=/usr/local/bin/monitor.sh
Restart=always

[Install]
WantedBy=multi-user.target
EOL

    systemctl enable pakhsheshkon-monitor v2ray
    systemctl start pakhsheshkon-monitor v2ray

    echo -e "${GREEN}Abroad server setup completed!${NC}"
    echo -e "${GREEN}Server Name: $server_name${NC}"
    echo -e "${GREEN}V2Ray Port: $V2RAY_PORT${NC}"
    echo -e "${GREEN}Use this encrypted code in Iran panel: $UNIQUE_CODE${NC}"
fi

echo -e "${GREEN}Setup finished!${NC}"
