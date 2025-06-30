#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m'

# Log file
LOG_FILE="/var/log/pakhsheshkon-install.log"
exec 1>>"$LOG_FILE" 2>&1

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
        sleep 0.2
    done
    clear
    echo -e "${GREEN}${LOGO}${NC}"
}

# Generate random string
generate_random_string() {
    openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 16
}

# Check server resources
check_resources() {
    echo -e "${YELLOW}Checking server resources...${NC}"
    CPU_CORES=$(nproc)
    RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
    DISK_MB=$(df -m / | awk 'NR==2 {print $4}')
    
    if [[ $CPU_CORES -lt 1 || $RAM_MB -lt 512 || $DISK_MB -lt 2048 ]]; then
        echo -e "${RED}Insufficient resources! Minimum: 1 CPU core, 512MB RAM, 2GB free disk.${NC}"
        echo -e "${YELLOW}Current: $CPU_CORES cores, $RAM_MB MB RAM, $DISK_MB MB disk.${NC}"
        exit 1
    fi
    echo -e "${GREEN}Resources OK: $CPU_CORES cores, $RAM_MB MB RAM, $DISK_MB MB disk.${NC}"
}

# Backup server
backup_server() {
    echo -e "${YELLOW}Creating server backup...${NC}"
    BACKUP_FILE="/root/pakhsheshkon-backup-$(date +%F).tar.gz"
    tar -czf "$BACKUP_FILE" /etc /var/www 2>/dev/null
    echo -e "${GREEN}Backup saved to $BACKUP_FILE${NC}"
}

# Main menu
animate_logo
echo -e "${YELLOW}Welcome to Pakhshesh Kon!${NC}"
check_resources
backup_server

echo -e "${CYAN}Choose an option:${NC}"
echo -e "1) Install Pakhshesh Kon"
echo -e "2) Uninstall Pakhshesh Kon"
echo -e "3) Exit"
read -p "Enter your choice (1-3): " choice

if [[ "$choice" == "2" ]]; then
    echo -e "${RED}Uninstalling Pakhshesh Kon...${NC}"
    systemctl stop apache2 nginx mariadb v2ray pakhsheshkon-monitor 2>/dev/null
    systemctl disable apache2 nginx mariadb v2ray pakhsheshkon-monitor 2>/dev/null
    rm -rf /var/www/html/* /etc/pakhsheshkon /usr/local/etc/v2ray /usr/local/bin/monitor.sh
    rm -f /etc/systemd/system/pakhsheshkon-monitor.service
    rm -f /etc/apache2/sites-available/pakhsheshkon.conf /etc/nginx/sites-available/pakhsheshkon
    DB_NAME=$(mysql -e "SHOW DATABASES LIKE 'pk_%'" | grep pk_ || echo "")
    if [[ -n "$DB_NAME" ]]; then
        mysql -e "DROP DATABASE $DB_NAME;"
    fi
    apt purge -y apache2 nginx php php-mysql mariadb-server unzip curl libapache2-mod-php composer v2ray vnstat fail2ban
    apt autoremove -y
    ufw reset --force
    ufw enable
    echo -e "${GREEN}Pakhshesh Kon completely uninstalled! Server is now clean.${NC}"
    exit 0
elif [[ "$choice" != "1" ]]; then
    echo -e "${YELLOW}Exiting...${NC}"
    exit 0
fi

# Detect country
COUNTRY=$(curl -s https://ipapi.co/country_name/ || echo "Unknown")
SERVER_IP=$(curl -s ifconfig.me)
echo -e "${YELLOW}Detected server location: $COUNTRY (IP: $SERVER_IP)${NC}"

# Server type selection
echo -e "${CYAN}Select server type:${NC}"
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
    # Web server selection
    echo -e "${CYAN}Select web server:${NC}"
    echo -e "1) Apache"
    echo -e "2) Nginx"
    read -p "Enter your choice (1-2): " web_server
    if [[ "$web_server" == "1" ]]; then
        WEB_SERVER="apache"
        apt install -y apache2 libapache2-mod-php
        systemctl enable apache2
        systemctl start apache2
    elif [[ "$web_server" == "2" ]]; then
        WEB_SERVER="nginx"
        apt install -y nginx
        systemctl enable nginx
        systemctl start nginx
    else
        echo -e "${RED}Invalid choice! Defaulting to Apache.${NC}"
        WEB_SERVER="apache"
        apt install -y apache2 libapache2-mod-php
        systemctl enable apache2
        systemctl start apache2
    fi

    # Install dependencies
    echo -e "${YELLOW}Installing dependencies...${NC}"
    apt install -y php php-mysql mariadb-server unzip curl composer certbot python3-certbot-$WEB_SERVER fail2ban

    # Setup fail2ban
    echo -e "${YELLOW}Configuring fail2ban...${NC}"
    systemctl enable fail2ban
    systemctl start fail2ban

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
    echo -e "${YELLOW}Enter domain for panel (e.g., panel.example.com, leave blank for no domain):${NC}"
    read -p "Domain: " DOMAIN
    echo -e "${YELLOW}Enter base URL path (e.g., xxx for domain.com/xxx, leave blank for root):${NC}"
    read -p "Base URL: " BASE_URL
    BASE_URL=${BASE_URL:-"pakhsheshkon"}
    DOCUMENT_ROOT="/var/www/html/$BASE_URL"

    # Check domain
    USE_SSL="no"
    if [[ -n "$DOMAIN" ]]; then
        echo -e "${YELLOW}Checking domain DNS...${NC}"
        DOMAIN_IP=$(dig +short "$DOMAIN" | tail -n1)
        if [[ "$DOMAIN_IP" != "$SERVER_IP" ]]; then
            echo -e "${RED}Domain $DOMAIN does not point to this server ($SERVER_IP). Please update DNS.${NC}"
            exit 1
        fi

        # Check Cloudflare proxy
        CF_RAY=$(curl -s -I "http://$DOMAIN" | grep -i "CF-RAY" || echo "")
        if [[ -n "$CF_RAY" ]]; then
            echo -e "${RED}Cloudflare proxy detected! Please disable proxy (orange cloud) for $DOMAIN.${NC}"
            read -p "Continue without SSL? (y/n): " continue_without_ssl
            if [[ "$continue_without_ssl" != "y" ]]; then
                exit 1
            fi
        else
            echo -e "${YELLOW}Installing SSL for $DOMAIN...${NC}"
            if certbot --$WEB_SERVER -d "$DOMAIN" --non-interactive --agree-tos --email "admin@$DOMAIN"; then
                USE_SSL="yes"
            else
                echo -e "${RED}SSL installation failed. Continuing without SSL.${NC}"
            fi
        fi
    fi

    # Download and extract panel
    echo -e "${YELLOW}Downloading panel...${NC}"
    mkdir -p "$DOCUMENT_ROOT"
    curl -L -o panel.zip https://github.com/mahdikbk/pakhshesh-kon/releases/latest/download/panel.zip
    unzip panel.zip -d "$DOCUMENT_ROOT"
    mv "$DOCUMENT_ROOT/panel/"* "$DOCUMENT_ROOT/"
    rm -rf "$DOCUMENT_ROOT/panel" panel.zip

    # Install composer dependencies
    composer require endroid/qr-code -d "$DOCUMENT_ROOT"

    # Configure database
    cat > "$DOCUMENT_ROOT/includes/config.php" <<EOL
<?php
define('DB_HOST', 'localhost');
define('DB_NAME', '$DB_NAME');
define('DB_USER', '$DB_USER');
define('DB_PASS', '$DB_PASS');
define('SECRET_KEY', '$(generate_random_string)');
define('BASE_URL', '$BASE_URL');
?>
EOL

    # Create database tables
    mysql -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" <<EOF
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
    chown -R www-data:www-data "$DOCUMENT_ROOT"
    chmod -R 755 "$DOCUMENT_ROOT"

    # Configure web server
    if [[ "$WEB_SERVER" == "apache" ]]; then
        cat > /etc/apache2/sites-available/pakhsheshkon.conf <<EOL
<VirtualHost *:80>
    ServerName ${DOMAIN:-localhost}
    DocumentRoot $DOCUMENT_ROOT
    <Directory $DOCUMENT_ROOT>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    ErrorLog \${APACHE_LOG_DIR}/pakhsheshkon-error.log
    CustomLog \${APACHE_LOG_DIR}/pakhsheshkon-access.log combined
</VirtualHost>
EOL
        if [[ "$USE_SSL" == "yes" ]]; then
            sed -i 's/:80/:443/' /etc/apache2/sites-available/pakhsheshkon.conf
            echo "    SSLEngine on" >> /etc/apache2/sites-available/pakhsheshkon.conf
            echo "    SSLCertificateFile /etc/letsencrypt/live/$DOMAIN/fullchain.pem" >> /etc/apache2/sites-available/pakhsheshkon.conf
            echo "    SSLCertificateKeyFile /etc/letsencrypt/live/$DOMAIN/privkey.pem" >> /etc/apache2/sites-available/pakhsheshkon.conf
        fi
        a2ensite pakhsheshkon.conf
        a2enmod rewrite
        systemctl restart apache2
    else
        cat > /etc/nginx/sites-available/pakhsheshkon <<EOL
server {
    listen 80;
    server_name ${DOMAIN:-localhost};
    root $DOCUMENT_ROOT;
    index index.php;
    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
}
EOL
        if [[ "$USE_SSL" == "yes" ]]; then
            sed -i 's/listen 80;/listen 443 ssl;/' /etc/nginx/sites-available/pakhsheshkon
            echo "    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;" >> /etc/nginx/sites-available/pakhsheshkon
            echo "    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;" >> /etc/nginx/sites-available/pakhsheshkon
        fi
        ln -sf /etc/nginx/sites-available/pakhsheshkon /etc/nginx/sites-enabled/
        systemctl restart nginx
    fi

    PROTOCOL="http"
    [[ "$USE_SSL" == "yes" ]] && PROTOCOL="https"
    PANEL_URL="${PROTOCOL}://${DOMAIN:-$SERVER_IP}/$BASE_URL"
    echo -e "${GREEN}Installation completed! Access panel at $PANEL_URL${NC}"
    echo -e "${GREEN}Admin Username: $admin_user${NC}"
    echo -e "${GREEN}Admin Password: [Your chosen password]${NC}"

else
    # Install dependencies for abroad server
    echo -e "${YELLOW}Installing V2Ray and dependencies...${NC}"
    apt install -y curl unzip ufw vnstat fail2ban

    # Setup fail2ban
    echo -e "${YELLOW}Configuring fail2ban...${NC}"
    systemctl enable fail2ban
    systemctl start fail2ban

    # Install Cloudflare WARP
    echo -e "${CYAN}Install Cloudflare WARP for optimized traffic? (y/n)${NC}"
    read -p "Choice: " install_warp
    if [[ "$install_warp" == "y" ]]; then
        echo -e "${YELLOW}Installing Cloudflare WARP...${NC}"
        curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
        echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ focal main" > /etc/apt/sources.list.d/cloudflare-client.list
        apt update
        apt install -y cloudflare-warp
        warp-cli register
        warp-cli connect
    fi

    # Get server name
    echo -e "${YELLOW}Enter a name for this server (e.g., Finland-1):${NC}"
    read -p "Server Name: " server_name

    # Generate random port
    V2RAY_PORT=$((RANDOM % 10000 + 10000))
    echo -e "${YELLOW}Generated V2Ray port: $V2RAY_PORT${NC}"

    # Install V2Ray
    bash <(curl -L https://github.com/v2fly/v2ray-core/releases/latest/download/install-release.sh)

    # Generate encrypted server code
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

    # Test connection to Iran server
    echo -e "${YELLOW}Enter Iran server IP for connection test (leave blank to skip):${NC}"
    read -p "Iran Server IP: " iran_ip
    if [[ -n "$iran_ip" ]]; then
        if curl -s -m 5 "http://$iran_ip" >/dev/null; then
            echo -e "${GREEN}Connection to Iran server ($iran_ip) successful!${NC}"
        else
            echo -e "${RED}Failed to connect to Iran server ($iran_ip). Please check network.${NC}"
        fi
    fi

    echo -e "${GREEN}Abroad server setup completed!${NC}"
    echo -e "${GREEN}Server Name: $server_name${NC}"
    echo -e "${GREEN}V2Ray Port: $V2RAY_PORT${NC}"
    echo -e "${GREEN}Use this encrypted code in Iran panel: $UNIQUE_CODE${NC}"
fi

echo -e "${GREEN}Setup finished! Log saved to $LOG_FILE${NC}"
