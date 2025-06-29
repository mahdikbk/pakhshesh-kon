#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ASCII Art Animation
clear
echo -e "${CYAN}"
cat << "EOF"
 ___          _      _            _                   _         _   _               
(  _`\       ( )    ( )          ( )                 ( )       ( ) ( )              
| |_) )  _ _ | |/') | |__    ___ | |__     __    ___ | |__     | |/'/'   _     ___  
| ,__/'/'_` )| , <  |  _ `\/',__)|  _ `\ /'__`\/',__)|  _ `\   | , <   /'_`\ /' _ `\
| |   ( (_| || |\`\ | | | |\__, \| | | |(  ___/\__, \| | | |   | |\`\ ( (_) )| ( ) |
(_)   `\__,_)(_) (_)(_) (_)(____/(_) (_)`\____)(____/(_) (_)   (_) (_)`\___/'(_) (_)
EOF
echo -e "${NC}"
sleep 1

clear
echo -e "${YELLOW}"
cat << "EOF"
 ___          _      _            _                   _         _   _               
(  _`\       ( )    ( )          ( )                 ( )       ( ) ( )              
| |_) )  _ _ | |/') | |__    ___ | |__     __    ___ | |__     | |/'/'   _     ___  
| ,__/'/'_` )| , <  |  _ `\/',__)|  _ `\ /'__`\/',__)|  _ `\   | , <   /'_`\ /' _ `\
| |   ( (_| || |\`\ | | | |\__, \| | | |(  ___/\__, \| | | |   | |\`\ ( (_) )| ( ) |
(_)   `\__,_)(_) (_)(_) (_)(____/(_) (_)`\____)(____/(_) (_)   (_) (_)`\___/'(_) (_)
EOF
echo -e "${NC}"
sleep 1

clear
echo -e "${GREEN}"
cat << "EOF"
 ___          _      _            _                   _         _   _               
(  _`\       ( )    ( )          ( )                 ( )       ( ) ( )              
| |_) )  _ _ | |/') | |__    ___ | |__     __    ___ | |__     | |/'/'   _     ___  
| ,__/'/'_` )| , <  |  _ `\/',__)|  _ `\ /'__`\/',__)|  _ `\   | , <   /'_`\ /' _ `\
| |   ( (_| || |\`\ | | | |\__, \| | | |(  ___/\__, \| | | |   | |\`\ ( (_) )| ( ) |
(_)   `\__,_)(_) (_)(_) (_)(____/(_) (_)`\____)(____/(_) (_)   (_) (_)`\___/'(_) (_)
EOF
echo -e "${NC}"
echo -e "${YELLOW}Welcome to Pakhshesh Kon Installer!${NC}"
sleep 2

# Generate random string
generate_random_string() {
    openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 16
}

echo -e "${YELLOW}Is this server in Iran or Abroad? (iran/abroad)${NC}"
read -p "Enter your choice: " server_location

# Validate input
if [[ "$server_location" != "iran" && "$server_location" != "abroad" ]]; then
    echo -e "${RED}Invalid choice! Please enter 'iran' or 'abroad'.${NC}"
    exit 1
fi

# Update system
echo -e "${YELLOW}Updating system...${NC}"
apt update && apt upgrade -y

if [[ "$server_location" == "iran" ]]; then
    # Install dependencies
    echo -e "${YELLOW}Installing Apache, PHP, MariaDB, and dependencies...${NC}"
    apt install -y apache2 php php-mysql mariadb-server unzip curl libapache2-mod-php composer

    # Start and enable services
    systemctl enable apache2
    systemctl start apache2
    systemctl enable mariadb
    systemctl start mariadb

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

    # Download and extract panel
    echo -e "${YELLOW}Downloading and setting up panel...${NC}"
    curl -L -o panel.zip https://github.com/mahdikbk/pakhshesh-kon/releases/latest/download/panel.zip
    unzip panel.zip -d /var/www/html/
    mv /var/www/html/panel/* /var/www/html/
    rm -rf /var/www/html/panel panel.zip

    # Install composer dependencies
    composer require endroid/qr-code -d /var/www/html

    # Configure database
    cat > /var/www/html/includes/config.php <<EOL
<?php
define('DB_HOST', 'localhost');
define('DB_NAME', '$DB_NAME');
define('DB_USER', '$DB_USER');
define('DB_PASS', '$DB_PASS');
define('SECRET_KEY', '$(generate_random_string)');
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
CREATE TABLE servers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(15) NOT NULL,
    port INT NOT NULL,
    name VARCHAR(50),
    unique_code VARCHAR(64) NOT NULL,
    group_id INT NOT NULL,
    status ENUM('active', 'inactive') DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE server_groups (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
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
    chown -R www-data:www-data /var/www/html
    chmod -R 755 /var/www/html

    # Configure Apache
    cat > /etc/apache2/sites-available/pakhsheshkon.conf <<EOL
<VirtualHost *:80>
    ServerName localhost
    DocumentRoot /var/www/html
    <Directory /var/www/html>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    ErrorLog \${APACHE_LOG_DIR}/pakhsheshkon-error.log
    CustomLog \${APACHE_LOG_DIR}/pakhsheshkon-access.log combined
</VirtualHost>
EOL

    a2ensite pakhsheshkon.conf
    a2enmod rewrite
    systemctl restart apache2

    echo -e "${GREEN}Installation completed! Access panel at http://$(curl -s ifconfig.me)/${NC}"
    echo -e "${GREEN}Admin Username: $admin_user${NC}"
    echo -e "${GREEN}Admin Password: [Your chosen password]${NC}"

else
    # Install dependencies for abroad server
    echo -e "${YELLOW}Installing V2Ray and dependencies...${NC}"
    apt install -y curl unzip ufw vnstat

    # Get server name and group
    echo -e "${YELLOW}Enter a name for this server (e.g., Finland-1):${NC}"
    read -p "Server Name: " server_name
    echo -e "${YELLOW}Enter server group (e.g., Europe, Asia, America):${NC}"
    read -p "Group Name: " server_group

    # Generate random port
    V2RAY_PORT=$((RANDOM % 10000 + 10000))
    echo -e "${YELLOW}Generated V2Ray port: $V2RAY_PORT${NC}"

    # Install V2Ray
    bash <(curl -L https://github.com/v2fly/v2ray-core/releases/latest/download/install-release.sh)

    # Generate encrypted server code
    SERVER_IP=$(curl -s ifconfig.me)
    SECRET_KEY=$(generate_random_string)
    SERVER_DATA=$(echo -n "$SERVER_IP|$V2RAY_PORT|$server_name|$server_group")
    UNIQUE_CODE=$(echo -n "$SERVER_DATA" | openssl dgst -sha256 -hmac "$SECRET_KEY" | head -c 64)
    echo -e "${GREEN}Encrypted Server Code: $UNIQUE_CODE${NC}"

    # Save server config
    cat > /etc/pakhsheshkon/server.conf <<EOL
SERVER_IP=$SERVER_IP
V2RAY_PORT=$V2RAY_PORT
SERVER_NAME=$server_name
SERVER_GROUP=$server_group
SECRET_KEY=$SECRET_KEY
UNIQUE_CODE=$UNIQUE_CODE
EOL

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

    systemctl enable pakhsheshkon-monitor
    systemctl start pakhsheshkon-monitor

    # Ensure V2Ray starts on boot
    systemctl enable v2ray
    systemctl start v2ray

    echo -e "${GREEN}Abroad server setup completed!${NC}"
    echo -e "${GREEN}Server Name: $server_name${NC}"
    echo -e "${GREEN}Server Group: $server_group${NC}"
    echo -e "${GREEN}V2Ray Port: $V2RAY_PORT${NC}"
    echo -e "${GREEN}Use this encrypted code in Iran panel: $UNIQUE_CODE${NC}"
fi

echo -e "${GREEN}Setup finished!${NC}"
