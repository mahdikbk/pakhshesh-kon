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

# ASCII Art for Powered By MahdiKBK
POWERED_BY=$(cat << 'EOF'
   _                            _                               _     
  |_) _        _  ._ _   _|    |_)       |\/|  _. |_   _| o |/ |_) |/ 
  |  (_) \/\/ (/_ | (/_ (_|    |_) \/    |  | (_| | | (_| | |\ |_) |\ 
                                   /                                  
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
    echo -e "${MAGENTA}${POWERED_BY}${NC}"
    sleep 1
    for color in RED GREEN YELLOW BLUE CYAN; do
        clear
        echo -e "${!color}${LOGO}${NC}"
        echo -e "${!color}${POWERED_BY}${NC}"
        sleep 0.2
    done
    clear
    echo -e "${GREEN}${LOGO}${NC}"
    echo -e "${NC}"
    for ((i=0; i<${#POWERED_BY}; i++)); do
        printf "\033[38;5;$((i*5+160))m${POWERED_BY:$i:1}"
    done
    echo -e "${NC}"
    sleep 1
}

# Generate random string
generate_random_string() {
    openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 32
}

# Detect server location
detect_location() {
    RESPONSE=$(curl -s http://ip-api.com/json)
    COUNTRY=$(echo "$RESPONSE" | jq -r '.country')
    CITY=$(echo "$RESPONSE" | jq -r '.city')
    ISP=$(echo "$RESPONSE" | jq -r '.isp')
    if [[ -z "$COUNTRY" || "$COUNTRY" == "null" ]]; then
        echo "Unable to detect location"
    else
        echo "$COUNTRY, $CITY, $ISP"
    fi
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

# Check server health
check_server_health() {
    CPU=$(grep -c processor /proc/cpuinfo)
    RAM=$(free -m | awk '/Mem:/ {print $2}')
    DISK=$(df -h / | awk 'NR==2 {print $4}' | tr -d 'G')
    if [[ $CPU -lt 1 || $RAM -lt 512 || $DISK -lt 5 ]]; then
        echo -e "${RED}Warning: Insufficient resources (CPU: $CPU, RAM: $RAM MB, Disk: $DISK GB)${NC}"
        read -p "Continue anyway? (y/n): " continue_health
        if [[ "$continue_health" != "y" ]]; then
            exit 1
        fi
    fi
}

# Log function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> /var/log/pakhsheshkon.log
}

# Main menu
animate_logo
echo -e "${YELLOW}Welcome to Pakhshesh Kon!${NC}"
SERVER_LOCATION=$(detect_location)
echo -e "${CYAN}Detected server location: $SERVER_LOCATION${NC}"
echo -e "${CYAN}Choose an option:${NC}"
echo -e "1) Install Pakhshesh Kon"
echo -e "2) Uninstall Pakhshesh Kon"
echo -e "3) Exit"
read -p "Enter your choice (1-3): " choice

if [[ "$choice" == "2" ]]; then
    echo -e "${RED}Uninstalling Pakhshesh Kon...${NC}"
    log "Starting uninstall process"
    systemctl stop apache2 mariadb v2ray pakhsheshkon-monitor 2>/dev/null
    systemctl disable apache2 mariadb v2ray pakhsheshkon-monitor 2>/dev/null
    rm -rf /var/www/html/* /etc/pakhsheshkon /usr/local/etc/v2ray /usr/local/bin/monitor.sh
    rm -f /etc/systemd/system/pakhsheshkon-monitor.service
    rm -f /etc/apache2/sites-available/pakhsheshkon.conf
    DB_NAME=$(mysql -e "SHOW DATABASES LIKE 'pk_%'" | grep pk_ || echo "")
    if [[ -n "$DB_NAME" ]]; then
        mysql -e "DROP DATABASE $DB_NAME;"
        log "Dropped database $DB_NAME"
    fi
    apt purge -y apache2 php php-mysql mariadb-server unzip curl libapache2-mod-php composer v2ray vnstat certbot python3-certbot-apache jq glances
    apt autoremove -y
    ufw reset --force
    ufw enable
    rm -rf /var/backups/pakhsheshkon
    log "Uninstall completed"
    echo -e "${GREEN}Pakhshesh Kon completely uninstalled! Server is now clean.${NC}"
    exit 0
elif [[ "$choice" != "1" ]]; then
    echo -e "${YELLOW}Exiting...${NC}"
    log "Installation aborted by user"
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
    log "Invalid server type selected"
    exit 1
fi

# Update system and install prerequisites
echo -e "${YELLOW}Updating system and installing prerequisites...${NC}"
log "Updating system"
apt update && apt upgrade -y
apt install -y curl jq unzip ntp
ntpdate pool.ntp.org
log "System updated and NTP synchronized"

# Check server health
check_server_health
log "Server health checked"

# Backup initial config
echo -e "${YELLOW}Creating initial backup...${NC}"
mkdir -p /var/backups/pakhsheshkon
tar -czf /var/backups/pakhsheshkon/initial_backup_$(date +%F).tar.gz /etc 2>/dev/null
log "Initial backup created"

if [[ "$server_location" == "iran" ]]; then
    # Install dependencies
    echo -e "${YELLOW}Installing Apache, PHP, MariaDB, Certbot, Glances, and dependencies...${NC}"
    apt install -y apache2 php php-mysql mariadb-server unzip curl libapache2-mod-php composer certbot python3-certbot-apache jq glances
    log "Installed dependencies for Iran server"

    # Start and enable services
    systemctl enable apache2 mariadb
    systemctl start apache2 mariadb
    log "Started Apache and MariaDB"

    # Secure MariaDB
    echo -e "${YELLOW}Securing MariaDB...${NC}"
    mysql_secure_installation <<EOF

y
y
y
y
y
EOF
    log "Secured MariaDB"

    # Create random database credentials
    echo -e "${YELLOW}Setting up database...${NC}"
    DB_NAME="pk_$(generate_random_string)"
    DB_USER="pkuser_$(generate_random_string)"
    DB_PASS=$(generate_random_string)
    mysql -e "CREATE DATABASE $DB_NAME;"
    mysql -e "CREATE USER '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';"
    mysql -e "GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';"
    mysql -e "FLUSH PRIVILEGES;"
    log "Created database $DB_NAME"

    # Get admin credentials
    echo -e "${YELLOW}Enter admin username for panel:${NC}"
    read -p "Username: " admin_user
    echo -e "${YELLOW}Enter admin password:${NC}"
    read -s -p "Password: " admin_pass
    echo
    log "Received admin credentials"

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
    log "Domain: $domain, Base URL: $base_url"

    # Check domain resolution
    echo -e "${YELLOW}Checking domain resolution...${NC}"
    if check_domain "$domain"; then
        echo -e "${GREEN}Domain $domain resolves to this server.${NC}"
        log "Domain $domain resolved successfully"
    else
        echo -e "${RED}Domain $domain does not resolve to this server's IP.${NC}"
        echo -e "${YELLOW}If using Cloudflare, ensure Proxy (orange cloud) is OFF and DNS is set to this server's IP.${NC}"
        read -p "Continue anyway? (y/n): " continue_domain
        if [[ "$continue_domain" != "y" ]]; then
            echo -e "${RED}Installation aborted.${NC}"
            log "Installation aborted due to domain resolution failure"
            exit 1
        fi
    fi

    # Setup SSL with HSTS
    echo -e "${YELLOW}Setting up SSL for $domain...${NC}"
    if certbot --apache -d "$domain" --non-interactive --agree-tos --email admin@$domain --hsts; then
        echo -e "${GREEN}SSL certificate installed successfully.${NC}"
        protocol="https"
        log "SSL installed for $domain"
    else
        echo -e "${RED}Failed to install SSL. Proceeding without SSL.${NC}"
        protocol="http"
        log "SSL installation failed, proceeding with HTTP"
    fi

    # Configure PHP
    echo -e "${YELLOW}Configuring PHP...${NC}"
    sed -i 's/upload_max_filesize = .*/upload_max_filesize = 10M/' /etc/php/*/apache2/php.ini
    sed -i 's/allow_url_fopen = .*/allow_url_fopen = Off/' /etc/php/*/apache2/php.ini
    sed -i 's/disable_functions = .*/disable_functions = exec,passthru,shell_exec,system/' /etc/php/*/apache2/php.ini
    log "Configured PHP settings"

    # Setup database backup cron
    echo -e "${YELLOW}Setting up daily database backup...${NC}"
    echo "0 2 * * * root mysqldump -u$DB_USER -p$DB_PASS $DB_NAME > /var/backups/pakhsheshkon/db_backup_$(date +%F).sql" >> /etc/crontab
    log "Configured daily database backup"

    # Download and extract panel
    echo -e "${YELLOW}Downloading panel...${NC}"
    curl -L -o panel.zip https://github.com/mahdikbk/pakhshesh-kon/releases/latest/download/panel.zip
    unzip panel.zip -d /var/www/html/panel_tmp
    mv /var/www/html/panel_tmp/panel/* "$install_path/"
    rm -rf /var/www/html/panel_tmp panel.zip
    log "Downloaded and extracted panel"

    # Install composer dependencies
    composer require endroid/qr-code -d "$install_path"
    log "Installed Composer dependencies"

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
    log "Created config.php"

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
    log "Created database tables"

    # Set permissions
    chown -R www-data:www-data "$install_path"
    chmod -R 755 "$install_path"
    log "Set file permissions"

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
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    ErrorLog \${APACHE_LOG_DIR}/pakhsheshkon-ssl-error.log
    CustomLog \${APACHE_LOG_DIR}/pakhsheshkon-ssl-access.log combined
</VirtualHost>
EOL
    a2ensite pakhsheshkon.conf
    a2enmod rewrite ssl headers
    echo -e "${YELLOW}Optimizing Apache...${NC}"
    cat > /etc/apache2/conf-available/pakhsheshkon-optimize.conf <<EOL
<IfModule mod_deflate.c>
    AddOutputFilterByType DEFLATE text/html text/plain text/xml text/css application/javascript
</IfModule>
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 5
EOL
    a2enconf pakhsheshkon-optimize
    systemctl restart apache2
    log "Configured Apache with optimizations"

    echo -e "${GREEN}Installation completed! Access panel at $protocol://$domain${base_url:+/$base_url}/${NC}"
    echo -e "${GREEN}Admin Username: $admin_user${NC}"
    echo -e "${GREEN}Admin Password: [Your chosen password]${NC}"
    log "Iran server installation completed"

else
    # Install dependencies for abroad server
    echo -e "${YELLOW}Installing V2Ray and dependencies...${NC}"
    apt install -y curl unzip ufw vnstat jq
    log "Installed dependencies for abroad server"

    # Get server name
    echo -e "${YELLOW}Enter a name for this server (e.g., Finland-1):${NC}"
    read -p "Server Name: " server_name
    log "Server name: $server_name"

    # Generate random port
    V2RAY_PORT=$((RANDOM % 50000 + 10000))
    while netstat -tuln | grep -q ":$V2RAY_PORT"; do
        V2RAY_PORT=$((RANDOM % 50000 + 10000))
    done
    echo -e "${YELLOW}Generated V2Ray port: $V2RAY_PORT${NC}"
    log "Generated V2Ray port: $V2RAY_PORT"

    # Install V2Ray
    bash <(curl -L https://github.com/v2fly/v2ray-core/releases/latest/download/install-release.sh)
    log "Installed V2Ray"

    # Generate encrypted server code
    SERVER_IP=$(curl -s ifconfig.me)
    SECRET_KEY=$(generate_random_string)
    SERVER_DATA=$(echo -n "$SERVER_IP|$V2RAY_PORT|$server_name")
    UNIQUE_CODE=$(echo -n "$SERVER_DATA" | openssl dgst -sha256 -hmac "$SECRET_KEY" | head -c 64)
    echo -e "${GREEN}Encrypted Server Code: $UNIQUE_CODE${NC}"
    log "Generated server code: $UNIQUE_CODE"

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
    log "Saved server config"

    # Configure V2Ray with VLESS and VMess
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
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/letsencrypt/live/$SERVER_IP/fullchain.pem",
              "keyFile": "/etc/letsencrypt/live/$SERVER_IP/privkey.pem"
            }
          ]
        }
      }
    },
    {
      "port": $((V2RAY_PORT+1)),
      "protocol": "vmess",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "ws",
        "security": "none"
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
    log "Configured V2Ray"

    # Setup TLS for V2Ray
    echo -e "${YELLOW}Setting up TLS for V2Ray...${NC}"
    if certbot certonly --standalone -d "$SERVER_IP" --non-interactive --agree-tos --email admin@$SERVER_IP; then
        echo -e "${GREEN}TLS certificate installed for V2Ray.${NC}"
        log "TLS installed for V2Ray"
    else
        echo -e "${YELLOW}Using self-signed certificate for V2Ray...${NC}"
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/pakhsheshkon/v2ray.key -out /etc/pakhsheshkon/v2ray.crt -subj "/CN=$SERVER_IP"
        mv /etc/pakhsheshkon/v2ray.crt /etc/letsencrypt/live/$SERVER_IP/fullchain.pem
        mv /etc/pakhsheshkon/v2ray.key /etc/letsencrypt/live/$SERVER_IP/privkey.pem
        log "Generated self-signed certificate for V2Ray"
    fi

    # Optimize network
    echo -e "${YELLOW}Optimizing network...${NC}"
    sysctl -w net.core.rmem_max=8388608
    sysctl -w net.core.wmem_max=8388608
    sysctl -w net.ipv4.tcp_congestion_control=bbr
    echo "net.core.rmem_max=8388608" >> /etc/sysctl.conf
    echo "net.core.wmem_max=8388608" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p
    log "Optimized network settings"

    # Secure SSH
    echo -e "${YELLOW}Securing SSH...${NC}"
    SSH_PORT=$((RANDOM % 50000 + 10000))
    sed -i "s/#Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config
    sed -i "s/PermitRootLogin yes/PermitRootLogin no/" /etc/ssh/sshd_config
    systemctl restart sshd
    echo -e "${GREEN}SSH port changed to $SSH_PORT. Root login disabled.${NC}"
    log "Secured SSH with port $SSH_PORT"

    # Configure firewall
    ufw allow 80,443,$V2RAY_PORT,$((V2RAY_PORT+1)),$SSH_PORT/tcp
    ufw --force enable
    log "Configured firewall"

    # Setup monitoring
    echo -e "${YELLOW}Setting up monitoring...${NC}"
    curl -L -o /usr/local/bin/monitor.sh https://raw.githubusercontent.com/mahdikbk/pakhshesh-kon/main/scripts/monitor.sh
    chmod +x /usr/local/bin/monitor.sh
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
    log "Configured monitoring"

    # Check ping to Iran
    echo -e "${YELLOW}Checking ping to Iran server...${NC}"
    IRAN_IP=$(dig +short iran.pakhsheshkon.com || echo "1.1.1.1")
    PING=$(ping -c 4 $IRAN_IP | awk '/rtt/ {print $4}' | cut -d'/' -f2)
    if [[ -n "$PING" && $(echo "$PING > 200" | bc -l) -eq 1 ]]; then
        echo -e "${YELLOW}Warning: High ping to Iran ($PING ms). Performance may be affected.${NC}"
        log "High ping to Iran: $PING ms"
    else
        echo -e "${GREEN}Ping to Iran: $PING ms${NC}"
        log "Ping to Iran: $PING ms"
    fi

    echo -e "${GREEN}Abroad server setup completed!${NC}"
    echo -e "${GREEN}Server Name: $server_name${NC}"
    echo -e "${GREEN}V2Ray Port: $V2RAY_PORT${NC}"
    echo -e "${GREEN}Use this encrypted code in Iran panel: $UNIQUE_CODE${NC}"
    log "Abroad server installation completed"
fi

echo -e "${GREEN}Setup finished!${NC}"
log "Setup finished"
