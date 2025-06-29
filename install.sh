#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}Welcome to Pakhshesh Kon Installer!${NC}"
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
    # Install dependencies for Iran server
    echo -e "${YELLOW}Installing Apache, PHP, MariaDB, and other dependencies...${NC}"
    apt install -y apache2 php php-mysql mariadb-server unzip curl libapache2-mod-php

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

    # Create database
    echo -e "${YELLOW}Setting up database...${NC}"
    DB_NAME="pakhsheshkon"
    DB_USER="pakhsheshkon"
    DB_PASS=$(openssl rand -base64 12)
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

    # Configure database
    cat > /var/www/html/includes/config.php <<EOL
<?php
define('DB_HOST', 'localhost');
define('DB_NAME', '$DB_NAME');
define('DB_USER', '$DB_USER');
define('DB_PASS', '$DB_PASS');
?>
EOL

    # Create admins table and insert admin user
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
    server_id INT NOT NULL,
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
    unique_code VARCHAR(16) NOT NULL,
    name VARCHAR(50),
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

    # Install V2Ray
    bash <(curl -L https://github.com/v2fly/v2ray-core/releases/latest/download/install-release.sh)

    # Generate unique server code
    SERVER_IP=$(curl -s ifconfig.me)
    UNIQUE_CODE=$(echo -n "$SERVER_IP$(date +%s)" | sha256sum | head -c 16)
    echo -e "${GREEN}Unique Server Code: $UNIQUE_CODE${NC}"

    # Configure V2Ray
    curl -L -o /usr/local/etc/v2ray/config.json https://raw.githubusercontent.com/mahdikbk/pakhshesh-kon/main/scripts/v2ray-config.json

    # Configure firewall
    ufw allow 80,443,10000:20000/tcp
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
    echo -e "${GREEN}Use this unique code in Iran panel: $UNIQUE_CODE${NC}"
fi

echo -e "${GREEN}Setup finished!${NC}"
