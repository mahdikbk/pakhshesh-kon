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
echo "Starting Pakhshesh Kon installation at $(date)" >> "$LOG_FILE"

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
    echo "Logo animation displayed" >> "$LOG_FILE"
}

# Generate random string
generate_random_string() {
    if ! command -v openssl >/dev/null 2>&1; then
        echo -e "${RED}openssl not found! Installing...${NC}"
        apt install -y openssl || { echo -e "${RED}openssl installation failed!${NC}"; echo "openssl installation failed" >> "$LOG_FILE"; exit 1; }
    fi
    openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 16
}

# Check prerequisites
check_prerequisites() {
    echo -e "${YELLOW}Checking prerequisites...${NC}"
    for cmd in curl wget dig; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo -e "${YELLOW}Installing $cmd...${NC}"
            apt install -y "$cmd" || { echo -e "${RED}$cmd installation failed!${NC}"; echo "$cmd installation failed" >> "$LOG_FILE"; exit 1; }
        fi
    done
    echo -e "${GREEN}Prerequisites OK${NC}"
    echo "Prerequisites checked" >> "$LOG_FILE"
}

# Check network connectivity
check_network() {
    echo -e "${YELLOW}Checking network connectivity...${NC}"
    if ! ping -c 1 google.com >/dev/null 2>&1; then
        echo -e "${RED}No internet connection! Please check your network.${NC}"
        echo "Network check failed" >> "$LOG_FILE"
        exit 1
    fi
    echo -e "${GREEN}Network OK${NC}"
    echo "Network check passed" >> "$LOG_FILE"
}

# Check server resources
check_resources() {
    echo -e "${YELLOW}Checking server resources...${NC}"
    CPU_COUNT=$(nproc)
    RAM_TOTAL=$(free -m | awk '/^Mem:/{print $2}')
    DISK_FREE=$(df -h / | awk 'NR==2 {print $4}' | tr -d 'G')
    
    if [[ $CPU_COUNT -lt 1 || $RAM_TOTAL -lt 512 || $DISK_FREE -lt 5 ]]; then
        echo -e "${RED}Insufficient resources! Need at least 1 CPU, 512MB RAM, 5GB disk.${NC}"
        echo "Resource check failed: CPU=$CPU_COUNT, RAM=$RAM_TOTAL MB, Disk=$DISK_FREE GB" >> "$LOG_FILE"
        exit 1
    fi
    echo -e "${GREEN}Resources OK: $CPU_COUNT CPUs, $RAM_TOTAL MB RAM, $DISK_FREE GB disk free${NC}"
    echo "Resources checked" >> "$LOG_FILE"
}

# Backup server
backup_server() {
    echo -e "${YELLOW}Creating server backup...${NC}"
    BACKUP_DIR="/root/pakhsheshkon-backup-$(date +%F-%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    tar -czf "$BACKUP_DIR/etc.tar.gz" /etc 2>/dev/null
    tar -czf "$BACKUP_DIR/www.tar.gz" /var/www 2>/dev/null
    echo -e "${GREEN}Backup saved to $BACKUP_DIR${NC}"
    echo "Backup created at $BACKUP_DIR" >> "$LOG_FILE"
}

# Detect country
detect_country() {
    echo -e "${YELLOW}Detecting server location...${NC}"
    SERVER_IP=$(curl -s ifconfig.me || echo "Unknown")
    COUNTRY=$(curl -s https://ipapi.co/country_name/ || echo "Unknown")
    echo -e "${CYAN}Server detected in: $COUNTRY (IP: $SERVER_IP)${NC}"
    echo "Detected country: $COUNTRY, IP: $SERVER_IP" >> "$LOG_FILE"
}

# Main menu
animate_logo
check_prerequisites
check_network
check_resources
backup_server
detect_country
echo -e "${YELLOW}Welcome to Pakhshesh Kon!${NC}"
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
        mysql -e "DROP DATABASE $DB_NAME;" 2>/dev/null
    fi
    apt purge -y apache2 nginx php php-mysql mariadb-server unzip curl libapache2-mod-php composer v2ray vnstat certbot python3-certbot-apache python3-certbot-nginx fail2ban 2>/dev/null
    apt autoremove -y 2>/dev/null
    ufw reset --force 2>/dev/null
    ufw enable 2>/dev/null
    echo -e "${GREEN}Pakhshesh Kon completely uninstalled! Server is now clean.${NC}"
    echo "Uninstallation completed" >> "$LOG_FILE"
    exit 0
elif [[ "$choice" != "1" ]]; then
    echo -e "${YELLOW}Exiting...${NC}"
    echo "User exited" >> "$LOG_FILE"
    exit 0
fi

# Select server type
echo -e "${CYAN}Select server type:${NC}"
echo -e "1) Iran"
echo -e "2) Abroad"
read -p "Enter your choice (1-2): " server_type
if [[ "$server_type" == "1" ]]; then
    server_location="iran"
elif [[ "$server_type" == "2" ]]; then
    server_location="abroad"
else
    echo -e "${RED}Invalid choice!${NC}"
    echo "Invalid server type choice: $server_type" >> "$LOG_FILE"
    exit 1
fi

# Update system
echo -e "${YELLOW}Updating system...${NC}"
apt update && apt upgrade -y || { echo -e "${RED}System update failed!${NC}"; echo "System update failed" >> "$LOG_FILE"; exit 1; }

if [[ "$server_location" == "iran" ]]; then
    # Select web server
    echo -e "${CYAN}Select web server:${NC}"
    echo -e "1) Apache"
    echo -e "2) Nginx"
    read -p "Enter your choice (1-2): " web_server
    if [[ "$web_server" == "1" ]]; then
        WEB_SERVER_PKG="apache2 libapache2-mod-php"
        WEB_SERVER_NAME="apache"
    elif [[ "$web_server" == "2" ]]; then
        WEB_SERVER_PKG="nginx"
        WEB_SERVER_NAME="nginx"
    else
        echo -e "${RED}Invalid choice!${NC}"
        echo "Invalid web server choice: $web_server" >> "$LOG_FILE"
        exit 1
    fi

    # Install dependencies
    echo -e "${YELLOW}Installing $WEB_SERVER_NAME, PHP, MariaDB, and dependencies...${NC}"
    apt install -y $WEB_SERVER_PKG php php-mysql mariadb-server unzip curl composer certbot python3-certbot-$WEB_SERVER_NAME fail2ban || { echo -e "${RED}Installation failed!${NC}"; echo "Dependency installation failed" >> "$LOG_FILE"; exit 1; }

    # Start and enable services
    systemctl enable $WEB_SERVER_NAME mariadb || { echo -e "${RED}Service enable failed!${NC}"; echo "Service enable failed" >> "$LOG_FILE"; exit 1; }
    systemctl start $WEB_SERVER_NAME mariadb

    # Configure fail2ban
    echo -e "${YELLOW}Configuring fail2ban...${NC}"
    cat > /etc/fail2ban/jail.local <<EOL
[sshd]
enabled = true
port = ssh
maxretry = 5
bantime = 3600
EOL
    systemctl enable fail2ban
    systemctl start fail2ban
    echo "Fail2ban configured" >> "$LOG_FILE"

    # Secure MariaDB
    echo -e "${YELLOW}Securing MariaDB...${NC}"
    mysql_secure_installation <<EOF

y
y
y
y
y
EOF
    echo "MariaDB secured" >> "$LOG_FILE"

    # Create random database credentials
    echo -e "${YELLOW}Setting up database...${NC}"
    DB_NAME="pk_$(generate_random_string)"
    DB_USER="pkuser_$(generate_random_string)"
    DB_PASS=$(generate_random_string)
    mysql -e "CREATE DATABASE $DB_NAME;" || { echo -e "${RED}Database creation failed!${NC}"; echo "Database creation failed" >> "$LOG_FILE"; exit 1; }
    mysql -e "CREATE USER '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';"
    mysql -e "GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';"
    mysql -e "FLUSH PRIVILEGES;"
    echo "Database setup: $DB_NAME, user: $DB_USER" >> "$LOG_FILE"

    # Get admin credentials
    echo -e "${YELLOW}Enter admin username for panel:${NC}"
    read -p "Username: " admin_user
    echo -e "${YELLOW}Enter admin password:${NC}"
    read -s -p "Password: " admin_pass
    echo
    echo "Admin credentials set" >> "$LOG_FILE"

    # Get domain and base URL
    echo -e "${YELLOW}Enter domain for panel (e.g., panel.example.com, leave empty for no domain):${NC}"
    read -p "Domain: " DOMAIN
    echo -e "${YELLOW}Enter base URL path (e.g., xxx for domain.com/xxx, leave empty for root):${NC}"
    read -p "Base URL: " BASE_URL
    BASE_URL=${BASE_URL:-"panel"}
    DOCUMENT_ROOT="/var/www/html/$BASE_URL"

    # Check domain
    if [[ -n "$DOMAIN" ]]; then
        echo -e "${YELLOW}Checking domain DNS...${NC}"
        DOMAIN_IP=$(dig +short "$DOMAIN" | tail -n1 || echo "")
        if [[ -z "$DOMAIN_IP" || "$DOMAIN_IP" != "$SERVER_IP" ]]; then
            echo -e "${RED}Domain $DOMAIN does not point to this server ($SERVER_IP)!${NC}"
            echo "Domain check failed: $DOMAIN_IP != $SERVER_IP" >> "$LOG_FILE"
            exit 1
        fi
        # Check Cloudflare proxy
        CF_RAY=$(curl -s -I "http://$DOMAIN" | grep -i "CF-RAY" || echo "")
        if [[ -n "$CF_RAY" ]]; then
            echo -e "${RED}Cloudflare proxy detected! Please disable proxy for $DOMAIN and try again.${NC}"
            echo "Cloudflare proxy detected" >> "$LOG_FILE"
            exit 1
        fi
        # Install SSL
        echo -e "${YELLOW}Installing SSL for $DOMAIN...${NC}"
        if ! certbot --$WEB_SERVER_NAME -d "$DOMAIN" --non-interactive --agree-tos --email "admin@$DOMAIN" 2>>"$LOG_FILE"; then
            echo -e "${YELLOW}SSL installation failed, continuing with HTTP...${NC}"
            PROTOCOL="http"
            echo "SSL installation failed" >> "$LOG_FILE"
        else
            PROTOCOL="https"
            echo "SSL installed" >> "$LOG_FILE"
        fi
    else
        DOMAIN="localhost"
        PROTOCOL="http"
        echo "No domain specified, using localhost" >> "$LOG_FILE"
    fi

    # Download and extract panel
    echo -e "${YELLOW}Downloading panel...${NC}"
    curl -L -o panel.zip https://github.com/mahdikbk/pakhshesh-kon/releases/latest/download/panel.zip || { echo -e "${RED}Download failed! Check your network or GitHub repository.${NC}"; echo "Panel download failed" >> "$LOG_FILE"; exit 1; }
    mkdir -p "$DOCUMENT_ROOT"
    unzip panel.zip -d "$DOCUMENT_ROOT" || { echo -e "${RED}Unzip failed!${NC}"; echo "Unzip failed" >> "$LOG_FILE"; exit 1; }
    mv "$DOCUMENT_ROOT/panel/"* "$DOCUMENT_ROOT/"
    rm -rf "$DOCUMENT_ROOT/panel" panel.zip
    echo "Panel extracted to $DOCUMENT_ROOT" >> "$LOG_FILE"

    # Install composer dependencies
    composer require endroid/qr-code -d "$DOCUMENT_ROOT" || { echo -e "${RED}Composer failed!${NC}"; echo "Composer failed" >> "$LOG_FILE"; exit 1; }
    echo "Composer dependencies installed" >> "$LOG_FILE"

    # Configure database
    cat > "$DOCUMENT_ROOT/includes/config.php" <<EOL
<?php
define('DB_HOST', 'localhost');
define('DB_NAME', '$DB_NAME');
define('DB_USER', '$DB_USER');
define('DB_PASS', '$DB_PASS');
define('SECRET_KEY', '$(generate_random_string)');
define('BASE_URL', '/$BASE_URL');
?>
EOL
    echo "Database config created" >> "$LOG_FILE"

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
    echo "Database tables created" >> "$LOG_FILE"

    # Set permissions
    chown -R www-data:www-data "$DOCUMENT_ROOT"
    chmod -R 755 "$DOCUMENT_ROOT"
    echo "Permissions set for $DOCUMENT_ROOT" >> "$LOG_FILE"

    # Configure web server
    if [[ "$WEB_SERVER_NAME" == "apache" ]]; then
        cat > /etc/apache2/sites-available/pakhsheshkon.conf <<EOL
<VirtualHost *:80>
    ServerName $DOMAIN
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
        a2ensite pakhsheshkon.conf
        a2enmod rewrite
        systemctl restart apache2
        echo "Apache configured" >> "$LOG_FILE"
    else
        cat > /etc/nginx/sites-available/pakhsheshkon <<EOL
server {
    listen 80;
    server_name $DOMAIN;
    root $DOCUMENT_ROOT;
    index index.php;
    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }
}
EOL
        ln -s /etc/nginx/sites-available/pakhsheshkon /etc/nginx/sites-enabled/
        systemctl restart nginx
        echo "Nginx configured" >> "$LOG_FILE"
    fi

    echo -e "${GREEN}Installation completed! Access panel at $PROTOCOL://$DOMAIN/$BASE_URL${NC}"
    echo -e "${GREEN}Admin Username: $admin_user${NC}"
    echo -e "${GREEN}Admin Password: [Your chosen password]${NC}"
    echo "Iran server installation completed: $PROTOCOL://$DOMAIN/$BASE_URL" >> "$LOG_FILE"

else
    # Install WARP option
    echo -e "${CYAN}Install Cloudflare WARP for optimized traffic? (y/n)${NC}"
    read -p "Choice: " install_warp
    if [[ "$install_warp" == "y" ]]; then
        echo -e "${YELLOW}Installing Cloudflare WARP...${NC}"
        curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
        echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ focal main" | tee /etc/apt/sources.list.d/cloudflare-client.list
        apt update
        apt install -y cloudflare-warp || { echo -e "${RED}WARP installation failed!${NC}"; echo "WARP installation failed" >> "$LOG_FILE"; exit 1; }
        warp-cli --accept-tos register
        warp-cli --accept-tos connect
        echo "Cloudflare WARP installed" >> "$LOG_FILE"
    fi

    # Install dependencies
    echo -e "${YELLOW}Installing V2Ray and dependencies...${NC}"
    apt install -y curl unzip ufw vnstat fail2ban || { echo -e "${RED}Installation failed!${NC}"; echo "Dependency installation failed" >> "$LOG_FILE"; exit 1; }

    # Configure fail2ban
    echo -e "${YELLOW}Configuring fail2ban...${NC}"
    cat > /etc/fail2ban/jail.local <<EOL
[sshd]
enabled = true
port = ssh
maxretry = 5
bantime = 3600
EOL
    systemctl enable fail2ban
    systemctl start fail2ban
    echo "Fail2ban configured" >> "$LOG_FILE"

    # Get server name
    echo -e "${YELLOW}Enter a name for this server (e.g., Finland-1):${NC}"
    read -p "Server Name: " server_name

    # Generate random port
    V2RAY_PORT=$((RANDOM % 10000 + 10000))
    echo -e "${YELLOW}Generated V2Ray port: $V2RAY_PORT${NC}"
    echo "V2Ray port: $V2RAY_PORT" >> "$LOG_FILE"

    # Install V2Ray
    bash <(curl -L https://github.com/v2fly/v2ray-core/releases/latest/download/install-release.sh) || { echo -e "${RED}V2Ray installation failed!${NC}"; echo "V2Ray installation failed" >> "$LOG_FILE"; exit 1; }

    # Generate encrypted server code
    SERVER_IP=$(curl -s ifconfig.me)
    SECRET_KEY=$(generate_random_string)
    SERVER_DATA=$(echo -n "$SERVER_IP|$V2RAY_PORT|$server_name")
    UNIQUE_CODE=$(echo -n "$SERVER_DATA" | openssl dgst -sha256 -hmac "$SECRET_KEY" | head -c 64)
    echo -e "${GREEN}Encrypted Server Code: $UNIQUE_CODE${NC}"
    echo "Server code generated: $UNIQUE_CODE" >> "$LOG_FILE"

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
    echo "Server config saved" >> "$LOG_FILE"

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
    echo "V2Ray configured" >> "$LOG_FILE"

    # Configure firewall
    ufw allow 80,443,$V2RAY_PORT/tcp
    ufw --force enable
    echo "Firewall configured" >> "$LOG_FILE"

    # Download and setup monitoring script
    curl -L -o /usr/local/bin/monitor.sh https://raw.githubusercontent.com/mahdikbk/pakhshesh-kon/main/scripts/monitor.sh || { echo -e "${RED}Monitor script download failed!${NC}"; echo "Monitor script download failed" >> "$LOG_FILE"; exit 1; }
    chmod +x /usr/local/bin/monitor.sh
    echo "Monitoring script installed" >> "$LOG_FILE"

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
    echo "Monitoring service configured" >> "$LOG_FILE"

    # Test connection to Iran server
    echo -e "${YELLOW}Enter Iran server IP for connection test (or press Enter to skip):${NC}"
    read -p "Iran Server IP: " IRAN_IP
    if [[ -n "$IRAN_IP" ]]; then
        if ping -c 3 "$IRAN_IP" >/dev/null 2>&1; then
            echo -e "${GREEN}Connection to Iran server ($IRAN_IP) successful!${NC}"
            echo "Connection test to $IRAN_IP successful" >> "$LOG_FILE"
        else
            echo -e "${RED}Connection to Iran server ($IRAN_IP) failed! Please check network.${NC}"
            echo "Connection test to $IRAN_IP failed" >> "$LOG_FILE"
        fi
    fi

    echo -e "${GREEN}Abroad server setup completed!${NC}"
    echo -e "${GREEN}Server Name: $server_name${NC}"
    echo -e "${GREEN}V2Ray Port: $V2RAY_PORT${NC}"
    echo -e "${GREEN}Use this encrypted code in Iran panel: $UNIQUE_CODE${NC}"
    echo "Abroad server installation completed" >> "$LOG_FILE"
fi

echo -e "${GREEN}Setup finished! Log saved to $LOG_FILE${NC}"
echo "Installation finished at $(date)" >> "$LOG_FILE"
