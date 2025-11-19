#!/bin/bash

# ============================================
# پخشش کن! - اسکریپت نصب خودکار و حرفه‌ای
# نسخه 2.0.0 - ساختار MVC حرفه‌ای
# ============================================

set -e  # Exit on error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# ASCII Art
LOGO=$(cat << 'EOF'
    ___          _      _            _                   _         _   _               
   (  _`\       ( )    ( )          ( )                 ( )       ( ) ( )              
   | |_) )  _ _ | |/') | |__    ___ | |__     __    ___ | |__     | |/'/'   _     ___  
   | ,__/'/'_` )| , <  |  _ `\/',__)|  _ `\ /'__`\/',__)|  _ `\   | , <   /'_`\ /' _ `\
   | |   ( (_| || |\`\ | | | |\__, \| | | |(  ___/\__, \| | | |   | |\`\ ( (_) )| ( ) |
   (_)   `\__,_)(_) (_)(_) (_)(____/(_) (_)`\____)(____/(_) (_)   (_) (_)`\___/'(_) (_)
EOF
)

POWERED_BY=$(cat << 'EOF'
   _                            _                               _     
  |_) _        _  ._ _   _|    |_)       |\/|  _. |_   _| o |/ |_) |/ 
  |  (_) \/\/ (/_ | (/_ (_|    |_) \/    |  | (_| | | (_| | |\ |_) |\ 
                                   /                                  
EOF
)

# Functions
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> /var/log/pakhsheshkon.log
    echo -e "${CYAN}[LOG]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    log "ERROR: $1"
    exit 1
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    log "SUCCESS: $1"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    log "WARNING: $1"
}

progress() {
    echo -e "${YELLOW}⏳ $1...${NC}"
}

# Generate random string
generate_random_string() {
    openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 32 2>/dev/null || \
    cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 32
}

# Generate UUID
generate_uuid() {
    if command -v uuidgen >/dev/null 2>&1; then
        uuidgen | tr '[:upper:]' '[:lower:]' | tr -d '-'
    else
        cat /proc/sys/kernel/random/uuid 2>/dev/null | tr -d '-' || \
        openssl rand -hex 16 | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/\1-\2-\3-\4-\5/'
    fi
}

# Detect server location automatically
detect_server_location() {
    progress "Detecting server location"
    
    # Try multiple IP geolocation services
    IP=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || \
         curl -s --max-time 5 http://ip.me 2>/dev/null || \
         curl -s --max-time 5 http://icanhazip.com 2>/dev/null || \
         echo "")
    
    if [[ -z "$IP" ]]; then
        warning "Could not detect IP, assuming abroad server"
        echo "abroad"
        return
    fi
    
    # Check if IP is Iranian (common ranges)
    IRAN_RANGES=(
        "5.0.0.0/8"
        "37.0.0.0/8"
        "46.0.0.0/8"
        "78.0.0.0/8"
        "79.0.0.0/8"
        "85.0.0.0/8"
        "86.0.0.0/8"
        "87.0.0.0/8"
        "89.0.0.0/8"
        "91.0.0.0/8"
        "92.0.0.0/8"
        "93.0.0.0/8"
        "94.0.0.0/8"
        "95.0.0.0/8"
        "178.0.0.0/8"
        "185.0.0.0/8"
        "188.0.0.0/8"
        "212.0.0.0/8"
        "217.0.0.0/8"
    )
    
    # Simple check - if IP starts with common Iranian prefixes
    IP_FIRST_OCTET=$(echo $IP | cut -d. -f1)
    if [[ "$IP_FIRST_OCTET" == "5" ]] || [[ "$IP_FIRST_OCTET" == "37" ]] || \
       [[ "$IP_FIRST_OCTET" == "46" ]] || [[ "$IP_FIRST_OCTET" == "78" ]] || \
       [[ "$IP_FIRST_OCTET" == "79" ]] || [[ "$IP_FIRST_OCTET" == "85" ]] || \
       [[ "$IP_FIRST_OCTET" == "86" ]] || [[ "$IP_FIRST_OCTET" == "87" ]] || \
       [[ "$IP_FIRST_OCTET" == "89" ]] || [[ "$IP_FIRST_OCTET" == "91" ]] || \
       [[ "$IP_FIRST_OCTET" == "92" ]] || [[ "$IP_FIRST_OCTET" == "93" ]] || \
       [[ "$IP_FIRST_OCTET" == "94" ]] || [[ "$IP_FIRST_OCTET" == "95" ]] || \
       [[ "$IP_FIRST_OCTET" == "178" ]] || [[ "$IP_FIRST_OCTET" == "185" ]] || \
       [[ "$IP_FIRST_OCTET" == "188" ]] || [[ "$IP_FIRST_OCTET" == "212" ]] || \
       [[ "$IP_FIRST_OCTET" == "217" ]]; then
        echo "iran"
    else
        # Try API-based detection
        COUNTRY=$(curl -s --max-time 5 "http://ip-api.com/json/$IP?fields=countryCode" 2>/dev/null | \
                  grep -o '"countryCode":"[^"]*"' | cut -d'"' -f4 || echo "")
        
        if [[ "$COUNTRY" == "IR" ]]; then
            echo "iran"
        else
            echo "abroad"
        fi
    fi
}

# Get server IP
get_server_ip() {
    curl -s --max-time 5 https://api.ipify.org 2>/dev/null || \
    curl -s --max-time 5 http://ip.me 2>/dev/null || \
    curl -s --max-time 5 http://icanhazip.com 2>/dev/null || \
    hostname -I | awk '{print $1}' || \
    ip route get 8.8.8.8 | awk '{print $7; exit}'
}

# Check if domain exists and resolves
check_domain_exists() {
    local domain=$1
    local server_ip=$(get_server_ip)
    
    # Try to resolve domain
    local resolved_ip=$(dig +short "$domain" @8.8.8.8 2>/dev/null | tail -n1 || \
                        dig +short "$domain" @1.1.1.1 2>/dev/null | tail -n1 || \
                        getent hosts "$domain" 2>/dev/null | awk '{print $1}' | head -n1)
    
    if [[ -n "$resolved_ip" ]]; then
        if [[ "$resolved_ip" == "$server_ip" ]]; then
            return 0  # Domain resolves to this server
        else
            return 1  # Domain exists but points elsewhere
        fi
    fi
    
    return 2  # Domain doesn't resolve
}

# Auto-detect domain
auto_detect_domain() {
    local server_ip=$(get_server_ip)
    
    # Try reverse DNS
    local rdomain=$(dig +short -x "$server_ip" @8.8.8.8 2>/dev/null | sed 's/\.$//' || echo "")
    
    if [[ -n "$rdomain" ]] && check_domain_exists "$rdomain"; then
        echo "$rdomain"
        return
    fi
    
    # Try common patterns
    local hostname=$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo "")
    if [[ -n "$hostname" ]] && [[ "$hostname" != "localhost" ]] && check_domain_exists "$hostname"; then
        echo "$hostname"
        return
    fi
    
    # Return IP as fallback
    echo "$server_ip"
}

# Main installation function
main() {
    clear
    echo -e "${CYAN}$LOGO${NC}"
    echo -e "${MAGENTA}$POWERED_BY${NC}"
    echo ""
    
    info "Starting automatic installation..."
    log "Installation started"
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root. Use: sudo bash install.sh"
    fi
    
    # Detect OS
    if [[ ! -f /etc/os-release ]]; then
        error "Unsupported operating system"
    fi
    
    source /etc/os-release
    if [[ "$ID" != "ubuntu" ]] && [[ "$ID" != "debian" ]]; then
        error "This script supports Ubuntu/Debian only"
    fi
    
    # Update system
    progress "Updating system packages"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1
    apt-get upgrade -y -qq >/dev/null 2>&1
    
    # Install essential packages
    progress "Installing essential packages"
    apt-get install -y -qq \
        curl wget git unzip \
        apache2 php php-mysql php-mbstring php-xml php-curl php-zip \
        mariadb-server mariadb-client \
        certbot python3-certbot-apache \
        jq uuid-runtime net-tools \
        vnstat bc ntpdate \
        >/dev/null 2>&1
    
    # Sync time
    ntpdate -q pool.ntp.org >/dev/null 2>&1 || timedatectl set-ntp true
    
    # Detect server location automatically
    SERVER_LOCATION=$(detect_server_location)
    SERVER_IP=$(get_server_ip)
    
    info "Detected server location: $SERVER_LOCATION"
    info "Server IP: $SERVER_IP"
    log "Server location: $SERVER_LOCATION, IP: $SERVER_IP"
    
    if [[ "$SERVER_LOCATION" == "iran" ]]; then
        install_iran_server
    else
        install_abroad_server
    fi
}

# Install Iran server (Panel)
install_iran_server() {
    info "Installing Iran server (Panel)..."
    
    # Start MariaDB
    progress "Starting MariaDB"
    systemctl start mariadb >/dev/null 2>&1
    systemctl enable mariadb >/dev/null 2>&1
    
    # Secure MariaDB (non-interactive)
    progress "Securing MariaDB"
    mysql -e "SET PASSWORD FOR 'root'@'localhost' = PASSWORD('$(generate_random_string)');" 2>/dev/null || true
    mysql -e "DELETE FROM mysql.user WHERE User='';" 2>/dev/null || true
    mysql -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');" 2>/dev/null || true
    mysql -e "DROP DATABASE IF EXISTS test;" 2>/dev/null || true
    mysql -e "FLUSH PRIVILEGES;" 2>/dev/null || true
    
    # Create database
    progress "Creating database"
    DB_NAME="pk_$(generate_random_string | tr '[:upper:]' '[:lower:]')"
    DB_USER="pkuser_$(generate_random_string | tr '[:upper:]' '[:lower:]')"
    DB_PASS=$(generate_random_string)
    
    mysql -e "CREATE DATABASE IF NOT EXISTS $DB_NAME CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" || \
        error "Failed to create database"
    mysql -e "CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';" || \
        error "Failed to create database user"
    mysql -e "GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';" || \
        error "Failed to grant privileges"
    mysql -e "FLUSH PRIVILEGES;"
    
    # Auto-detect or use IP as domain
    progress "Detecting domain"
    DOMAIN=$(auto_detect_domain)
    
    if [[ "$DOMAIN" == "$SERVER_IP" ]]; then
        warning "No domain detected, using IP address"
        BASE_URL=""
        PROTOCOL="http"
    else
        BASE_URL=""
        PROTOCOL="https"
    fi
    
    # Install V2Ray
    progress "Installing V2Ray"
    bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh) >/dev/null 2>&1 || \
        error "Failed to install V2Ray"
    
    # Generate V2Ray port
    V2RAY_PORT=$((RANDOM % 50000 + 10000))
    while netstat -tuln 2>/dev/null | grep -q ":$V2RAY_PORT" || ss -tuln 2>/dev/null | grep -q ":$V2RAY_PORT"; do
        V2RAY_PORT=$((RANDOM % 50000 + 10000))
    done
    
    # Setup SSL if domain exists
    if [[ "$DOMAIN" != "$SERVER_IP" ]] && [[ "$PROTOCOL" == "https" ]]; then
        progress "Setting up SSL certificate"
        certbot certonly --standalone -d "$DOMAIN" --non-interactive --agree-tos \
            --email "admin@$DOMAIN" --quiet >/dev/null 2>&1 || \
            warning "SSL certificate generation failed, continuing without SSL"
    fi
    
    # Configure V2Ray
    progress "Configuring V2Ray"
    mkdir -p /usr/local/etc/v2ray
    
    if [[ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]]; then
        CERT_FILE="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
        KEY_FILE="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
    else
        # Self-signed certificate
        mkdir -p /etc/letsencrypt/live/$DOMAIN
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/letsencrypt/live/$DOMAIN/privkey.pem \
            -out /etc/letsencrypt/live/$DOMAIN/fullchain.pem \
            -subj "/CN=$DOMAIN" >/dev/null 2>&1
        CERT_FILE="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
        KEY_FILE="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
    fi
    
    cat > /usr/local/etc/v2ray/config.json <<EOF
{
  "log": {
    "access": "/var/log/v2ray/access.log",
    "error": "/var/log/v2ray/error.log",
    "loglevel": "warning"
  },
  "inbounds": [{
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
        "certificates": [{
          "certificateFile": "$CERT_FILE",
          "keyFile": "$KEY_FILE"
        }]
      }
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {}
  }]
}
EOF
    
    mkdir -p /var/log/v2ray
    systemctl enable v2ray >/dev/null 2>&1
    systemctl restart v2ray >/dev/null 2>&1
    
    # Save V2Ray port
    mkdir -p /etc/pakhsheshkon
    echo "$V2RAY_PORT" > /etc/pakhsheshkon/iran_port.txt
    chmod 600 /etc/pakhsheshkon/iran_port.txt
    
    # Create admin user (auto-generated)
    ADMIN_USER="admin"
    ADMIN_PASS=$(generate_random_string)
    
    # Install path
    if [[ -z "$BASE_URL" ]]; then
        INSTALL_PATH="/var/www/html"
    else
        INSTALL_PATH="/var/www/html/$BASE_URL"
        mkdir -p "$INSTALL_PATH"
    fi
    
    # Copy project files
    progress "Copying project files"
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    # Create directory structure
    mkdir -p "$INSTALL_PATH"/{src,public,views,config,database/migrations,tests,storage/logs}
    mkdir -p "$INSTALL_PATH"/public/{assets/{css,js,fonts},qrcodes}
    mkdir -p "$INSTALL_PATH"/src/{Core,Models,Controllers,Services,Middleware,Helpers}
    mkdir -p "$INSTALL_PATH"/views/{layouts,auth,dashboard,users,servers,monitoring}
    mkdir -p "$INSTALL_PATH"/storage/{logs,backups,cache}
    
    # Copy source files if they exist
    if [[ -d "$SCRIPT_DIR/src" ]]; then
        cp -r "$SCRIPT_DIR/src"/* "$INSTALL_PATH/src/" 2>/dev/null || true
        cp -r "$SCRIPT_DIR/public"/* "$INSTALL_PATH/public/" 2>/dev/null || true
        cp -r "$SCRIPT_DIR/views"/* "$INSTALL_PATH/views/" 2>/dev/null || true
        [[ -d "$SCRIPT_DIR/config" ]] && cp -r "$SCRIPT_DIR/config"/* "$INSTALL_PATH/config/" 2>/dev/null || true
        [[ -d "$SCRIPT_DIR/database" ]] && cp -r "$SCRIPT_DIR/database"/* "$INSTALL_PATH/database/" 2>/dev/null || true
    else
        warning "Source files not found in script directory. Using default structure."
    fi
    
    # Copy composer.json and install dependencies
    if [[ -f "$SCRIPT_DIR/composer.json" ]]; then
        cp "$SCRIPT_DIR/composer.json" "$INSTALL_PATH/"
        progress "Installing Composer dependencies"
        cd "$INSTALL_PATH"
        
        # Install composer if not exists
        if ! command -v composer >/dev/null 2>&1; then
            curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer >/dev/null 2>&1
        fi
        
        # Install dependencies
        if command -v composer >/dev/null 2>&1; then
            composer install --no-interaction --no-dev --optimize-autoloader --quiet >/dev/null 2>&1 || \
                warning "Composer install had issues, continuing..."
        else
            warning "Composer installation failed, skipping dependency installation"
        fi
    else
        warning "composer.json not found, skipping dependency installation"
    fi
    
    # Create .env file
    progress "Creating configuration file"
    API_KEY=$(generate_random_string)
    CSRF_SECRET=$(generate_random_string)
    
    cat > "$INSTALL_PATH/.env" <<EOF
# Database
DB_HOST=localhost
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASS=$DB_PASS

# Application
APP_ENV=production
APP_DEBUG=false
APP_URL=$PROTOCOL://$DOMAIN
BASE_URL=$BASE_URL

# Security
CSRF_SECRET=$CSRF_SECRET
SESSION_LIFETIME=3600
RATE_LIMIT_ENABLED=true
RATE_LIMIT_MAX_ATTEMPTS=5
RATE_LIMIT_WINDOW=300
API_KEY=$API_KEY

# Telegram (optional)
TELEGRAM_ENABLED=false
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=

# V2Ray
V2RAY_IRAN_PORT=$V2RAY_PORT
V2RAY_CONFIG_PATH=/usr/local/etc/v2ray/config.json

# Backup
BACKUP_ENABLED=true
BACKUP_PATH=/var/backups/pakhsheshkon
BACKUP_RETENTION_DAYS=30

# Monitoring
MONITORING_INTERVAL=300
EOF
    
    chmod 600 "$INSTALL_PATH/.env"
    
    # Create database tables with new structure
    progress "Creating database tables"
    mysql -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" <<EOF
CREATE TABLE IF NOT EXISTS admins (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    last_login TIMESTAMP NULL,
    failed_login_attempts INT DEFAULT 0,
    locked_until TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    uuid VARCHAR(36) NOT NULL UNIQUE,
    server_group_id INT NOT NULL,
    traffic_limit BIGINT NOT NULL,
    traffic_used BIGINT DEFAULT 0,
    connection_limit INT NOT NULL,
    expiry_date DATE NOT NULL,
    qr_path VARCHAR(255),
    link TEXT,
    last_activity TIMESTAMP NULL,
    is_active TINYINT(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_username (username),
    INDEX idx_uuid (uuid),
    INDEX idx_server_group_id (server_group_id),
    INDEX idx_expiry_date (expiry_date),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS server_groups (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS servers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    group_id INT NOT NULL,
    ip VARCHAR(45) NOT NULL,
    port INT NOT NULL,
    name VARCHAR(50),
    unique_code VARCHAR(36) NOT NULL UNIQUE,
    status ENUM('active', 'inactive') DEFAULT 'active',
    last_check TIMESTAMP NULL,
    uptime_percentage DECIMAL(5,2) DEFAULT 100.00,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_group_id (group_id),
    INDEX idx_unique_code (unique_code),
    INDEX idx_status (status),
    INDEX idx_ip (ip),
    FOREIGN KEY (group_id) REFERENCES server_groups(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS monitoring (
    id INT AUTO_INCREMENT PRIMARY KEY,
    server_id INT NOT NULL,
    active_users INT,
    bandwidth VARCHAR(50),
    ping INT,
    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_server_id (server_id),
    INDEX idx_recorded_at (recorded_at),
    INDEX idx_server_recorded (server_id, recorded_at),
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS tickets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(100) NOT NULL,
    message TEXT NOT NULL,
    user_id INT NOT NULL,
    status ENUM('open', 'closed', 'pending') DEFAULT 'open',
    response TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_user_id (user_id),
    INDEX idx_status (status),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    action VARCHAR(255) NOT NULL,
    username VARCHAR(50),
    ip VARCHAR(45),
    level VARCHAR(20) DEFAULT 'INFO',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_username (username),
    INDEX idx_created_at (created_at),
    INDEX idx_level (level),
    INDEX idx_username_created (username, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert admin user
INSERT INTO admins (username, password) VALUES (
    '$ADMIN_USER',
    '$(php -r "echo password_hash('$ADMIN_PASS', PASSWORD_BCRYPT);")'
) ON DUPLICATE KEY UPDATE password=VALUES(password);

-- Insert default server group
INSERT INTO server_groups (name) VALUES ('Default') ON DUPLICATE KEY UPDATE name=name;
EOF
    
    # Download Yekan font
    progress "Downloading Yekan font"
    curl -L -o "$INSTALL_PATH/public/assets/fonts/Yekan.ttf" \
        https://github.com/DediData/Yekan-Font/raw/master/font/Yekan.ttf 2>/dev/null || \
        warning "Failed to download Yekan font"
    
    # Create .htaccess for routing
    cat > "$INSTALL_PATH/public/.htaccess" <<'HTACCESS_EOF'
RewriteEngine On
RewriteBase /

# Redirect all requests to index.php
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^(.*)$ index.php [QSA,L]

# Security headers
<IfModule mod_headers.c>
    Header set X-Content-Type-Options "nosniff"
    Header set X-Frame-Options "DENY"
    Header set X-XSS-Protection "1; mode=block"
    Header set Referrer-Policy "strict-origin-when-cross-origin"
</IfModule>

# Prevent access to sensitive files
<FilesMatch "^\.">
    Order allow,deny
    Deny from all
</FilesMatch>
HTACCESS_EOF
    
    # Configure Apache
    progress "Configuring Apache"
    cat > /etc/apache2/sites-available/pakhsheshkon.conf <<EOF
<VirtualHost *:80>
    ServerName $DOMAIN
    DocumentRoot $INSTALL_PATH/public
    
    <Directory $INSTALL_PATH/public>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    
    # Security
    <IfModule mod_headers.c>
        Header always set X-Content-Type-Options "nosniff"
        Header always set X-Frame-Options "DENY"
        Header always set X-XSS-Protection "1; mode=block"
    </IfModule>
    
    ErrorLog \${APACHE_LOG_DIR}/pakhsheshkon-error.log
    CustomLog \${APACHE_LOG_DIR}/pakhsheshkon-access.log combined
</VirtualHost>

$(if [[ "$PROTOCOL" == "https" ]] && [[ -f "$CERT_FILE" ]]; then
cat <<SSL_EOF
<VirtualHost *:443>
    ServerName $DOMAIN
    DocumentRoot $INSTALL_PATH/public
    
    <Directory $INSTALL_PATH/public>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    
    SSLEngine on
    SSLCertificateFile $CERT_FILE
    SSLCertificateKeyFile $KEY_FILE
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
    
    ErrorLog \${APACHE_LOG_DIR}/pakhsheshkon-ssl-error.log
    CustomLog \${APACHE_LOG_DIR}/pakhsheshkon-ssl-access.log combined
</VirtualHost>
SSL_EOF
fi)
EOF
    
    a2ensite pakhsheshkon.conf >/dev/null 2>&1
    a2dissite 000-default.conf >/dev/null 2>&1
    a2enmod rewrite ssl headers >/dev/null 2>&1
    
    # Apache optimization
    cat > /etc/apache2/conf-available/pakhsheshkon-optimize.conf <<EOF
<IfModule mod_deflate.c>
    AddOutputFilterByType DEFLATE text/html text/plain text/xml text/css application/javascript application/json
</IfModule>
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 5
EOF
    a2enconf pakhsheshkon-optimize >/dev/null 2>&1
    
    systemctl restart apache2 >/dev/null 2>&1
    
    # Setup firewall
    progress "Configuring firewall"
    ufw --force enable >/dev/null 2>&1
    ufw allow 22/tcp >/dev/null 2>&1
    ufw allow 80/tcp >/dev/null 2>&1
    ufw allow 443/tcp >/dev/null 2>&1
    ufw allow $V2RAY_PORT/tcp >/dev/null 2>&1
    
    # Set permissions
    progress "Setting permissions"
    chown -R www-data:www-data "$INSTALL_PATH"
    chmod -R 755 "$INSTALL_PATH"
    chmod -R 777 "$INSTALL_PATH/public/qrcodes" 2>/dev/null || true
    chmod -R 777 "$INSTALL_PATH/storage" 2>/dev/null || true
    chmod 600 "$INSTALL_PATH/.env"
    
    # Create storage directories with proper permissions
    mkdir -p "$INSTALL_PATH/storage/logs" "$INSTALL_PATH/storage/backups" "$INSTALL_PATH/storage/cache"
    chown -R www-data:www-data "$INSTALL_PATH/storage"
    chmod -R 775 "$INSTALL_PATH/storage"
    
    # Setup cron for backups
    progress "Setting up automatic backups"
    mkdir -p /var/backups/pakhsheshkon
    (crontab -l 2>/dev/null | grep -v "pakhsheshkon"; \
     echo "0 2 * * * mysqldump -u$DB_USER -p$DB_PASS $DB_NAME | gzip > /var/backups/pakhsheshkon/db_backup_\$(date +\\%Y-\\%m-\\%d).sql.gz 2>/dev/null") | crontab -
    
    # Save installation summary
    cat > /var/log/pakhsheshkon_install_summary.txt <<EOF
========================================
پخشش کن! - خلاصه نصب
========================================
تاریخ: $(date '+%Y-%m-%d %H:%M:%S')
نوع سرور: ایران (Panel)

اطلاعات دسترسی:
----------------
URL پنل: $PROTOCOL://$DOMAIN$([ -n "$BASE_URL" ] && echo "/$BASE_URL" || echo "")
نام کاربری: $ADMIN_USER
رمز عبور: $ADMIN_PASS

اطلاعات دیتابیس:
----------------
نام دیتابیس: $DB_NAME
کاربر دیتابیس: $DB_USER
رمز دیتابیس: $DB_PASS

اطلاعات V2Ray:
----------------
پورت V2Ray: $V2RAY_PORT

اطلاعات امنیتی:
----------------
API Key: $API_KEY
CSRF Secret: $CSRF_SECRET

========================================
⚠️  لطفاً این اطلاعات را در جای امن ذخیره کنید!
========================================
EOF
    
    chmod 600 /var/log/pakhsheshkon_install_summary.txt
    
    success "Installation completed successfully!"
    echo ""
    echo -e "${GREEN}════════════════════════════════════════${NC}"
    echo -e "${GREEN}   نصب با موفقیت انجام شد!${NC}"
    echo -e "${GREEN}════════════════════════════════════════${NC}"
    echo ""
    echo -e "${CYAN}📋 اطلاعات دسترسی:${NC}"
    echo -e "   URL: ${YELLOW}$PROTOCOL://$DOMAIN$([ -n "$BASE_URL" ] && echo "/$BASE_URL" || echo "")${NC}"
    echo -e "   نام کاربری: ${YELLOW}$ADMIN_USER${NC}"
    echo -e "   رمز عبور: ${YELLOW}$ADMIN_PASS${NC}"
    echo ""
    echo -e "${CYAN}📊 اطلاعات فنی:${NC}"
    echo -e "   V2Ray Port: ${YELLOW}$V2RAY_PORT${NC}"
    echo -e "   Database: ${YELLOW}$DB_NAME${NC}"
    echo ""
    echo -e "${YELLOW}⚠️  تمام اطلاعات در فایل زیر ذخیره شده:${NC}"
    echo -e "   ${CYAN}/var/log/pakhsheshkon_install_summary.txt${NC}"
    echo ""
    echo -e "${GREEN}✅ سیستم آماده استفاده است!${NC}"
    echo ""
}

# Install Abroad server
install_abroad_server() {
    info "Installing abroad server (V2Ray Node)..."
    
    # Get Iran panel info (try to auto-detect or ask minimal info)
    progress "Detecting Iran panel"
    
    # Try to find Iran panel from common patterns or ask
    IRAN_DOMAIN=""
    IRAN_BASE_URL=""
    
    # Try to detect from network or use default
    SERVER_NAME="Server-$(hostname | cut -d. -f1 || echo $(generate_random_string | head -c 8))"
    
    # Install V2Ray
    progress "Installing V2Ray"
    bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh) >/dev/null 2>&1 || \
        error "Failed to install V2Ray"
    
    # Generate V2Ray port
    V2RAY_PORT=$((RANDOM % 50000 + 10000))
    while netstat -tuln 2>/dev/null | grep -q ":$V2RAY_PORT" || ss -tuln 2>/dev/null | grep -q ":$V2RAY_PORT"; do
        V2RAY_PORT=$((RANDOM % 50000 + 10000))
    done
    
    # Generate unique code
    UNIQUE_CODE=$(generate_uuid)
    
    # Save server config
    mkdir -p /etc/pakhsheshkon
    cat > /etc/pakhsheshkon/server.conf <<EOF
SERVER_IP=$SERVER_IP
V2RAY_PORT=$V2RAY_PORT
SERVER_NAME=$SERVER_NAME
UNIQUE_CODE=$UNIQUE_CODE
IRAN_DOMAIN=$IRAN_DOMAIN
IRAN_BASE_URL=$IRAN_BASE_URL
EOF
    chmod 600 /etc/pakhsheshkon/server.conf
    
    # Configure V2Ray
    progress "Configuring V2Ray"
    mkdir -p /usr/local/etc/v2ray
    
    # Self-signed certificate
    mkdir -p /etc/letsencrypt/live/$SERVER_IP
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/letsencrypt/live/$SERVER_IP/privkey.pem \
        -out /etc/letsencrypt/live/$SERVER_IP/fullchain.pem \
        -subj "/CN=$SERVER_IP" >/dev/null 2>&1
    
    cat > /usr/local/etc/v2ray/config.json <<EOF
{
  "log": {
    "access": "/var/log/v2ray/access.log",
    "error": "/var/log/v2ray/error.log",
    "loglevel": "warning"
  },
  "inbounds": [{
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
        "certificates": [{
          "certificateFile": "/etc/letsencrypt/live/$SERVER_IP/fullchain.pem",
          "keyFile": "/etc/letsencrypt/live/$SERVER_IP/privkey.pem"
        }]
      }
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {}
  }]
}
EOF
    
    mkdir -p /var/log/v2ray
    systemctl enable v2ray >/dev/null 2>&1
    systemctl restart v2ray >/dev/null 2>&1
    
    # Network optimization
    progress "Optimizing network"
    sysctl -w net.core.rmem_max=8388608 >/dev/null 2>&1
    sysctl -w net.core.wmem_max=8388608 >/dev/null 2>&1
    sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1
    echo "net.core.rmem_max=8388608" >> /etc/sysctl.conf
    echo "net.core.wmem_max=8388608" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    
    # Setup monitoring script
    progress "Setting up monitoring"
    cat > /usr/local/bin/monitor.sh <<'MONITOR_EOF'
#!/bin/bash
source /etc/pakhsheshkon/server.conf

while true; do
    active_users=$(ss -tn 2>/dev/null | grep ESTAB | wc -l || echo 0)
    bandwidth=$(vnstat --oneline 2>/dev/null | cut -d';' -f11 || echo "0")
    ping=$(ping -c 2 -W 2 $IRAN_DOMAIN 2>/dev/null | awk '/rtt/ {print $4}' | cut -d'/' -f2 || echo "0")
    
    if [[ -n "$IRAN_DOMAIN" ]] && [[ "$IRAN_DOMAIN" != "" ]]; then
        PROTOCOL="https"
        URL="$PROTOCOL://$IRAN_DOMAIN${IRAN_BASE_URL:+/$IRAN_BASE_URL}/api/monitor"
        curl -s -X POST "$URL" \
            -H "X-API-Key: $(grep API_KEY /var/www/html/.env 2>/dev/null | cut -d'=' -f2 || echo '')" \
            -d "server_code=$UNIQUE_CODE&users=$active_users&bandwidth=$bandwidth&ping=$ping" \
            >/dev/null 2>&1 || true
    fi
    
    sleep 300
done
MONITOR_EOF
    
    chmod +x /usr/local/bin/monitor.sh
    
    # Create systemd service
    cat > /etc/systemd/system/pakhsheshkon-monitor.service <<EOF
[Unit]
Description=Pakhshesh Kon Monitoring Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/monitor.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable pakhsheshkon-monitor >/dev/null 2>&1
    systemctl start pakhsheshkon-monitor >/dev/null 2>&1
    
    # Setup firewall
    progress "Configuring firewall"
    ufw --force enable >/dev/null 2>&1
    ufw allow 22/tcp >/dev/null 2>&1
    ufw allow $V2RAY_PORT/tcp >/dev/null 2>&1
    
    # Save installation summary
    cat > /var/log/pakhsheshkon_install_summary.txt <<EOF
========================================
پخشش کن! - خلاصه نصب
========================================
تاریخ: $(date '+%Y-%m-%d %H:%M:%S')
نوع سرور: خارجی (V2Ray Node)

اطلاعات سرور:
----------------
نام سرور: $SERVER_NAME
IP سرور: $SERVER_IP
پورت V2Ray: $V2RAY_PORT

کد یکتای سرور:
----------------
$UNIQUE_CODE

⚠️  این کد را در پنل ایران وارد کنید!
========================================
EOF
    
    chmod 600 /var/log/pakhsheshkon_install_summary.txt
    
    success "Abroad server installation completed!"
    echo ""
    echo -e "${GREEN}════════════════════════════════════════${NC}"
    echo -e "${GREEN}   نصب سرور خارجی با موفقیت انجام شد!${NC}"
    echo -e "${GREEN}════════════════════════════════════════${NC}"
    echo ""
    echo -e "${CYAN}📋 اطلاعات سرور:${NC}"
    echo -e "   نام: ${YELLOW}$SERVER_NAME${NC}"
    echo -e "   IP: ${YELLOW}$SERVER_IP${NC}"
    echo -e "   پورت V2Ray: ${YELLOW}$V2RAY_PORT${NC}"
    echo ""
    echo -e "${CYAN}🔑 کد یکتای سرور:${NC}"
    echo -e "   ${YELLOW}$UNIQUE_CODE${NC}"
    echo ""
    echo -e "${YELLOW}⚠️  این کد را در پنل ایران وارد کنید!${NC}"
    echo ""
}

# Run main function
main "$@"
