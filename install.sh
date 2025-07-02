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

# Generate UUID
generate_uuid() {
    uuidgen | tr '[:upper:]' '[:lower:]' | tr -d '-'
}

# Detect server location
detect_location() {
    apt-get install -y jq uuid-runtime >/dev/null 2>&1
    RESPONSE=$(curl -s http://ip-api.com/json)
    if command -v jq >/dev/null 2>&1; then
        COUNTRY=$(echo "$RESPONSE" | jq -r '.country')
        CITY=$(echo "$RESPONSE" | jq -r '.city')
        ISP=$(echo "$RESPONSE" | jq -r '.isp')
    else
        COUNTRY=$(echo "$RESPONSE" | grep -oP '"country":"[^"]+"' | cut -d'"' -f4)
        CITY=$(echo "$RESPONSE" | grep -oP '"city":"[^"]+"' | cut -d'"' -f4)
        ISP=$(echo "$RESPONSE" | grep -oP '"isp":"[^"]+"' | cut -d'"' -f4)
    fi
    if [[ -z "$COUNTRY" || "$COUNTRY" == "null" ]]; then
        echo "Unable to detect location"
    else
        echo "$COUNTRY, $CITY, $ISP"
    fi
}

# Get server IP
get_server_ip() {
    SERVER_IP=$(curl -s https://api.ipify.org || curl -s http://ip.me)
    if [[ -z "$SERVER_IP" ]]; then
        echo -e "${RED}Failed to detect server IP. Please enter manually:${NC}"
        read -p "Server IP: " SERVER_IP
    fi
    echo "$SERVER_IP"
}

# Check domain resolves to server IP
check_domain() {
    DOMAIN=$1
    SERVER_IP=$(get_server_ip)
    RESOLVED_IP=$(dig @8.8.8.8 +short $DOMAIN | tail -n 1 || dig @1.1.1.1 +short $DOMAIN | tail -n 1)
    if [[ "$RESOLVED_IP" == "$SERVER_IP" ]]; then
        return 0
    else
        return 1
    fi
}

# Check server health
check_server_health() {
    progress_bar "Checking server health"
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
    echo -e "${GREEN}Server health OK${NC}"
    log "Server health checked"
}

# Log function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> /var/log/pakhsheshkon.log
}

# Progress bar
progress_bar() {
    echo -e "${YELLOW}$1 [          ]${NC}\r"
    for i in {1..10}; do
        echo -ne "${YELLOW}$1 [${GREEN}$(printf '%*s' $i | tr ' ' '#') $(printf '%*s' $((10-i)) )${YELLOW}] ${i}0%${NC}\r"
        sleep 0.5
    done
    echo -e "${YELLOW}$1 [${GREEN}########## OK${YELLOW}] 100%${NC}"
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
    progress_bar "Uninstalling Pakhshesh Kon"
    log "Starting uninstall process"
    systemctl stop apache2 mariadb v2ray pakhsheshkon-monitor 2>/dev/null
    systemctl disable apache2 mariadb v2ray pakhsheshkon-monitor 2>/dev/null
    rm -rf /var/www/html/* /etc/pakhsheshkon /usr/local/etc/v2ray /usr/local/bin/monitor.sh
    rm -f /etc/systemd/system/pakhsheshkon-monitor.service
    rm -f /etc/apache2/sites-available/pakhsheshkon.conf
    DB_NAME=$(mysql -e "SHOW DATABASES LIKE 'pk_%'" | grep pk_ || echo "")
    if [[ -n "$DB_NAME" ]]; then
        mysql -e "DROP DATABASE $DB_NAME;" 2>/dev/null
        log "Dropped database $DB_NAME"
    fi
    apt purge -y apache2 php php-mysql mariadb-server unzip curl libapache2-mod-php composer v2ray vnstat certbot python3-certbot-apache jq glances net-tools ntpdate bc uuid-runtime
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
progress_bar "Updating system"
log "Updating system"
apt update && apt upgrade -y
apt install -y curl jq unzip ntpdate net-tools apache2 php php-mysql mariadb-server libapache2-mod-php composer certbot python3-certbot-apache glances bc uuid-runtime
if command -v ntpdate >/dev/null 2>&1; then
    ntpdate pool.ntp.org 2>/dev/null
else
    timedatectl set-ntp true
    systemctl unmask systemd-timesyncd
    systemctl restart systemd-timesyncd
fi
log "System updated and time synchronized"

# Check server health
check_server_health

# Backup initial config
progress_bar "Creating initial backup"
mkdir -p /var/backups/pakhsheshkon
tar -czf /var/backups/pakhsheshkon/initial_backup_$(date +%F).tar.gz /etc 2>/dev/null
log "Initial backup created"

if [[ "$server_location" == "iran" ]]; then
    # Ensure MariaDB is running
    progress_bar "Starting MariaDB"
    systemctl start mariadb
    systemctl enable mariadb
    if ! systemctl is-active --quiet mariadb; then
        echo -e "${RED}MariaDB failed to start. Check logs in /var/log/mysql/.${NC}"
        log "MariaDB failed to start"
        exit 1
    fi
    log "MariaDB started"

    # Install V2Ray
    progress_bar "Installing V2Ray"
    bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh) || {
        echo -e "${RED}Failed to install V2Ray. Check network or repository.${NC}"
        log "V2Ray installation failed"
        exit 1
    }
    V2RAY_PORT=$((RANDOM % 50000 + 10000))
    while netstat -tuln | grep -q ":$V2RAY_PORT"; do
        V2RAY_PORT=$((RANDOM % 50000 + 10000))
    done
    echo -e "${YELLOW}Generated V2Ray port: $V2RAY_PORT${NC}"
    log "Generated V2Ray port: $V2RAY_PORT"

    # Configure V2Ray
    progress_bar "Configuring V2Ray"
    SERVER_IP=$(get_server_ip)
    mkdir -p /usr/local/etc/v2ray
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
              "certificateFile": "/etc/letsencrypt/live/$domain/fullchain.pem",
              "keyFile": "/etc/letsencrypt/live/$domain/privkey.pem"
            }
          ]
        }
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
    if certbot certonly --standalone -d "$domain" --non-interactive --agree-tos --email admin@$domain; then
        echo -e "${GREEN}TLS certificate installed for V2Ray.${NC}"
        log "TLS installed for V2Ray"
    else
        echo -e "${YELLOW}Using self-signed certificate for V2Ray...${NC}"
        mkdir -p /etc/letsencrypt/live/$domain
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/letsencrypt/live/$domain/privkey.pem -out /etc/letsencrypt/live/$domain/fullchain.pem -subj "/CN=$domain" 2>/dev/null
        log "Generated self-signed certificate for V2Ray"
    fi
    systemctl enable v2ray
    systemctl start v2ray
    if ! systemctl is-active --quiet v2ray; then
        echo -e "${RED}V2Ray service failed to start. Check logs in /usr/local/etc/v2ray/.${NC}"
        log "V2Ray service failed to start"
        exit 1
    fi
    log "V2Ray configured"

    # Save Iran V2Ray port
    progress_bar "Saving Iran V2Ray port"
    mkdir -p /etc/pakhsheshkon
    echo "$V2RAY_PORT" > /etc/pakhsheshkon/iran_port.txt
    chmod 600 /etc/pakhsheshkon/iran_port.txt
    log "Saved Iran V2Ray port"

    # Secure MariaDB
    progress_bar "Securing MariaDB"
    mysql_secure_installation <<EOF

y
y
y
y
y
EOF
    log "Secured MariaDB"

    # Create random database credentials
    progress_bar "Setting up database"
    DB_NAME="pk_$(generate_random_string)"
    DB_USER="pkuser_$(generate_random_string)"
    DB_PASS=$(generate_random_string)
    mysql -e "CREATE DATABASE $DB_NAME;" || {
        echo -e "${RED}Failed to create database. Check MariaDB status.${NC}"
        log "Database creation failed"
        exit 1
    }
    mysql -e "CREATE USER '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';"
    mysql -e "GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';"
    mysql -e "FLUSH PRIVILEGES;"
    log "Created database $DB_NAME"

    # Test database connection
    progress_bar "Testing database connection"
    if mysql -u$DB_USER -p$DB_PASS -e "SELECT 1" $DB_NAME >/dev/null 2>&1; then
        echo -e "${GREEN}Database connection successful${NC}"
        log "Database connection successful"
    else
        echo -e "${RED}Database connection failed${NC}"
        log "Database connection failed"
        exit 1
    fi

    # Get admin credentials
    progress_bar "Getting admin credentials"
    echo -e "${YELLOW}Enter admin username for panel:${NC}"
    read -p "Username: " admin_user
    echo -e "${YELLOW}Enter admin password:${NC}"
    read -s -p "Password: " admin_pass
    echo
    log "Received admin credentials"

    # Get domain and base URL
    progress_bar "Getting domain and base URL"
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
    progress_bar "Checking domain resolution"
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

    # Setup SSL
    progress_bar "Setting up SSL"
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
    progress_bar "Configuring PHP"
    sed -i 's/upload_max_filesize = .*/upload_max_filesize = 10M/' /etc/php/*/apache2/php.ini
    sed -i 's/allow_url_fopen = .*/allow_url_fopen = Off/' /etc/php/*/apache2/php.ini
    sed -i 's/disable_functions = .*/disable_functions = exec,passthru,shell_exec,system/' /etc/php/*/apache2/php.ini
    log "Configured PHP settings"

    # Setup database backup cron
    progress_bar "Setting up daily database backup"
    echo "0 2 * * * root mysqldump -u$DB_USER -p$DB_PASS $DB_NAME > /var/backups/pakhsheshkon/db_backup_$(date +%F).sql" >> /etc/crontab
    log "Configured daily database backup"

    # Create panel files
    progress_bar "Creating panel files"
    mkdir -p "$install_path/includes" "$install_path/assets/css" "$install_path/assets/js" "$install_path/assets/fonts" "$install_path/qrcodes"
    chmod 777 "$install_path/qrcodes"

    # index.php
    cat > "$install_path/index.php" <<'EOL'
<?php
session_start();
require_once 'includes/auth.php';

if (isLoggedIn()) {
    header('Location: dashboard.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];
    if (login($username, $password)) {
        header('Location: dashboard.php');
        exit;
    } else {
        $error = "نام کاربری یا رمز عبور اشتباه است.";
    }
}
?>
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ورود - پخشش کن!</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="assets/css/style.css" rel="stylesheet">
</head>
<body class="bg-gradient-to-br from-blue-900 to-indigo-800 min-h-screen flex items-center">
    <div class="container mx-auto px-4">
        <div class="max-w-md mx-auto bg-white rounded-2xl shadow-xl p-8">
            <h2 class="text-3xl font-bold text-center text-gray-800 mb-6">ورود به پنل</h2>
            <?php if (isset($error)) echo "<div class='bg-red-100 text-red-700 p-4 rounded-lg mb-4'>$error</div>"; ?>
            <form method="POST" class="space-y-6">
                <div>
                    <label for="username" class="block text-sm font-medium text-gray-700">نام کاربری</label>
                    <input type="text" id="username" name="username" class="mt-1 block w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500" required>
                </div>
                <div>
                    <label for="password" class="block text-sm font-medium text-gray-700">رمز عبور</label>
                    <input type="password" id="password" name="password" class="mt-1 block w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500" required>
                </div>
                <button type="submit" class="w-full bg-indigo-600 text-white p-3 rounded-lg hover:bg-indigo-700 transition duration-300">ورود</button>
            </form>
        </div>
    </div>
</body>
</html>
EOL

    # dashboard.php
    cat > "$install_path/dashboard.php" <<'EOL'
<?php
session_start();
require_once 'includes/auth.php';
require_once 'includes/functions.php';

if (!isLoggedIn()) {
    header('Location: index.php');
    exit;
}

$stats = getDashboardStats();
$traffic_data = $db->query("SELECT bandwidth, recorded_at FROM monitoring WHERE recorded_at >= DATE_SUB(NOW(), INTERVAL 5 DAY) ORDER BY recorded_at")->fetchAll();
$ping_data = $db->query("SELECT ping, server_id FROM monitoring WHERE recorded_at >= DATE_SUB(NOW(), INTERVAL 5 DAY) ORDER BY recorded_at")->fetchAll();
$users_data = $db->query("SELECT active_users, recorded_at FROM monitoring WHERE recorded_at >= DATE_SUB(NOW(), INTERVAL 5 DAY) ORDER BY recorded_at")->fetchAll();
$traffic_labels = json_encode(array_column($traffic_data, 'recorded_at'));
$traffic_values = json_encode(array_column($traffic_data, 'bandwidth'));
$ping_values = json_encode(array_column($ping_data, 'ping'));
$users_values = json_encode(array_column($users_data, 'active_users'));
?>
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>داشبورد - پخشش کن!</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="assets/css/style.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
</head>
<body class="bg-gray-100 min-h-screen">
    <?php include 'includes/nav.php'; ?>
    <div class="container mx-auto px-4 py-8">
        <h1 class="text-4xl font-bold text-gray-800 mb-8">خوش آمدید!</h1>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div class="bg-white rounded-2xl shadow-xl p-6">
                <h5 class="text-xl font-semibold text-gray-700">تعداد کاربران</h5>
                <p class="text-3xl text-indigo-600"><?php echo $stats['users']; ?></p>
            </div>
            <div class="bg-white rounded-2xl shadow-xl p-6">
                <h5 class="text-xl font-semibold text-gray-700">سرورهای فعال</h5>
                <p class="text-3xl text-indigo-600"><?php echo $stats['servers']; ?></p>
            </div>
            <div class="bg-white rounded-2xl shadow-xl p-6">
                <h5 class="text-xl font-semibold text-gray-700">ترافیک کل</h5>
                <p class="text-3xl text-indigo-600"><?php echo $stats['traffic']; ?> GB</p>
            </div>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mt-8">
            <div class="bg-white rounded-2xl shadow-xl p-6">
                <h5 class="text-xl font-semibold text-gray-700 mb-4">مصرف پهنای باند</h5>
                <canvas id="trafficChart"></canvas>
            </div>
            <div class="bg-white rounded-2xl shadow-xl p-6">
                <h5 class="text-xl font-semibold text-gray-700 mb-4">پینگ سرورها</h5>
                <canvas id="pingChart"></canvas>
            </div>
            <div class="bg-white rounded-2xl shadow-xl p-6">
                <h5 class="text-xl font-semibold text-gray-700 mb-4">کاربران فعال</h5>
                <canvas id="usersChart"></canvas>
            </div>
        </div>
    </div>
    <script src="assets/js/script.js"></script>
    <script>
        new Chart(document.getElementById('trafficChart'), {
            type: 'line',
            data: {
                labels: <?php echo $traffic_labels; ?>,
                datasets: [{
                    label: 'ترافیک (MB/s)',
                    data: <?php echo $traffic_values; ?>,
                    borderColor: '#4f46e5',
                    fill: false
                }]
            },
            options: { scales: { y: { beginAtZero: true } } }
        });
        new Chart(document.getElementById('pingChart'), {
            type: 'bar',
            data: {
                labels: <?php echo $traffic_labels; ?>,
                datasets: [{
                    label: 'پینگ (ms)',
                    data: <?php echo $ping_values; ?>,
                    backgroundColor: '#10b981'
                }]
            },
            options: { scales: { y: { beginAtZero: true } } }
        });
        new Chart(document.getElementById('usersChart'), {
            type: 'line',
            data: {
                labels: <?php echo $traffic_labels; ?>,
                datasets: [{
                    label: 'کاربران فعال',
                    data: <?php echo $users_values; ?>,
                    borderColor: '#ef4444',
                    fill: false
                }]
            },
            options: { scales: { y: { beginAtZero: true } } }
        });
    </script>
</body>
</html>
EOL

    # users.php
    cat > "$install_path/users.php" <<'EOL'
<?php
session_start();
require_once 'includes/auth.php';
require_once 'includes/functions.php';

if (!isLoggedIn()) {
    header('Location: index.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $traffic_limit = $_POST['traffic_limit'];
    $connection_limit = $_POST['connection_limit'];
    $days = $_POST['days'];
    $group_id = $_POST['group_id'];
    $result = createUser($username, $traffic_limit, $connection_limit, $days, $group_id);
    $success = "کاربر با موفقیت ایجاد شد! لینک: <a href='{$result['link']}' class='text-indigo-600'>{$result['link']}</a>";
}

$groups = $db->query("SELECT * FROM server_groups")->fetchAll();
$users = $db->query("SELECT u.*, g.name AS group_name FROM users u JOIN server_groups g ON u.server_group_id = g.id")->fetchAll();
?>
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>مدیریت کاربران - پخشش کن!</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="assets/css/style.css" rel="stylesheet">
</head>
<body class="bg-gray-100 min-h-screen">
    <?php include 'includes/nav.php'; ?>
    <div class="container mx-auto px-4 py-8">
        <h1 class="text-4xl font-bold text-gray-800 mb-8">مدیریت کاربران</h1>
        <?php if (isset($success)) echo "<div class='bg-green-100 text-green-700 p-4 rounded-lg mb-4'>$success</div>"; ?>
        <form method="POST" class="bg-white rounded-2xl shadow-xl p-6 mb-8">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                    <label for="username" class="block text-sm font-medium text-gray-700">نام کاربری</label>
                    <input type="text" id="username" name="username" class="mt-1 block w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500" required>
                </div>
                <div>
                    <label for="traffic_limit" class="block text-sm font-medium text-gray-700">محدودیت ترافیک (GB)</label>
                    <input type="number" id="traffic_limit" name="traffic_limit" class="mt-1 block w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500" required>
                </div>
                <div>
                    <label for="connection_limit" class="block text-sm font-medium text-gray-700">تعداد اتصال</label>
                    <input type="number" id="connection_limit" name="connection_limit" class="mt-1 block w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500" required>
                </div>
                <div>
                    <label for="days" class="block text-sm font-medium text-gray-700">مدت زمان (روز)</label>
                    <input type="number" id="days" name="days" class="mt-1 block w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500" required>
                </div>
                <div>
                    <label for="group_id" class="block text-sm font-medium text-gray-700">گروه سرور</label>
                    <select id="group_id" name="group_id" class="mt-1 block w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500" required>
                        <?php foreach ($groups as $group) {
                            echo "<option value='{$group['id']}'>{$group['name']}</option>";
                        } ?>
                    </select>
                </div>
            </div>
            <button type="submit" class="mt-6 w-full bg-indigo-600 text-white p-3 rounded-lg hover:bg-indigo-700 transition duration-300">ایجاد کاربر</button>
        </form>
        <h3 class="text-2xl font-semibold text-gray-700 mb-4">کاربران موجود</h3>
        <div class="bg-white rounded-2xl shadow-xl p-6">
            <table class="w-full">
                <thead>
                    <tr class="border-b">
                        <th class="py-3 px-4 text-right">نام کاربری</th>
                        <th class="py-3 px-4 text-right">گروه سرور</th>
                        <th class="py-3 px-4 text-right">ترافیک (GB)</th>
                        <th class="py-3 px-4 text-right">اتصال</th>
                        <th class="py-3 px-4 text-right">انقضا</th>
                        <th class="py-3 px-4 text-right">لینک</th>
                        <th class="py-3 px-4 text-right">QR کد</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($users as $user) {
                        echo "<tr class='border-b hover:bg-gray-50'>
                            <td class='py-3 px-4'>{$user['username']}</td>
                            <td class='py-3 px-4'>{$user['group_name']}</td>
                            <td class='py-3 px-4'>" . ($user['traffic_limit'] / (1024 * 1024 * 1024)) . "</td>
                            <td class='py-3 px-4'>{$user['connection_limit']}</td>
                            <td class='py-3 px-4'>{$user['expiry_date']}</td>
                            <td class='py-3 px-4'><a href='{$user['link']}' class='text-indigo-600 hover:underline'>لینک</a></td>
                            <td class='py-3 px-4'><button class='bg-indigo-600 text-white px-4 py-2 rounded-lg' data-bs-toggle='modal' data-bs-target='#qrModal{$user['id']}'>نمایش</button></td>
                        </tr>";
                        echo "<div class='modal fade fixed top-0 left-0 hidden w-full h-full bg-black bg-opacity-50' id='qrModal{$user['id']}' tabindex='-1'>
                            <div class='modal-dialog relative w-auto mx-auto max-w-md'>
                                <div class='modal-content bg-white rounded-2xl shadow-xl p-6'>
                                    <div class='modal-header flex justify-between items-center'>
                                        <h5 class='text-xl font-semibold text-gray-700'>QR کد برای {$user['username']}</h5>
                                        <button type='button' class='text-gray-500 hover:text-gray-700' data-bs-dismiss='modal'>×</button>
                                    </div>
                                    <div class='modal-body'>
                                        <img src='{$user['qr_path']}' class='w-full'>
                                        <a href='{$user['qr_path']}' download class='block mt-4 bg-indigo-600 text-white p-3 rounded-lg text-center hover:bg-indigo-700'>دانلود QR</a>
                                    </div>
                                </div>
                            </div>
                        </div>";
                    } ?>
                </tbody>
            </table>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.6/dist/umd/popper.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.min.js"></script>
</body>
</html>
EOL

    # servers.php
    cat > "$install_path/servers.php" <<'EOL'
<?php
session_start();
require_once 'includes/auth.php';
require_once 'includes/functions.php';
require_once 'includes/server-key.php';

if (!isLoggedIn()) {
    header('Location: index.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $code = $_POST['server_code'];
    $group_id = $_POST['group_id'];
    $ip = $_POST['ip'] ?? '';
    $port = $_POST['port'] ?? '';
    $name = $_POST['name'] ?? '';
    $serverData = decodeServerCode($code, $ip, $port, $name);

    if ($serverData) {
        global $db;
        $db->prepare("INSERT INTO servers (group_id, ip, port, name, unique_code) VALUES (?, ?, ?, ?, ?)")->execute([
            $group_id,
            $serverData['ip'],
            $serverData['port'],
            $serverData['name'],
            $code
        ]);
        $db->prepare("INSERT INTO logs (action, username, ip, created_at) VALUES (?, ?, ?, NOW())")->execute([
            "Server added: $name",
            $_SESSION['username'],
            $_SERVER['REMOTE_ADDR']
        ]);
        $success = "سرور با موفقیت به گروه اضافه شد!";
    } else {
        $error = "کد سرور نامعتبر است.";
        $db->prepare("INSERT INTO logs (action, username, ip, created_at) VALUES (?, ?, ?, NOW())")->execute([
            "Failed to add server: Invalid code $code",
            $_SESSION['username'],
            $_SERVER['REMOTE_ADDR']
        ]);
    }
}

$groups = $db->query("SELECT * FROM server_groups")->fetchAll();
$servers = $db->query("SELECT s.*, g.name AS group_name FROM servers s JOIN server_groups g ON s.group_id = g.id")->fetchAll();
?>
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>مدیریت سرورها - پخشش کن!</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="assets/css/style.css" rel="stylesheet">
</head>
<body class="bg-gray-100 min-h-screen">
    <?php include 'includes/nav.php'; ?>
    <div class="container mx-auto px-4 py-8">
        <h1 class="text-4xl font-bold text-gray-800 mb-8">مدیریت سرورها</h1>
        <?php if (isset($success)) echo "<div class='bg-green-100 text-green-700 p-4 rounded-lg mb-4'>$success</div>"; ?>
        <?php if (isset($error)) echo "<div class='bg-red-100 text-red-700 p-4 rounded-lg mb-4'>$error</div>"; ?>
        <form method="POST" class="bg-white rounded-2xl shadow-xl p-6 mb-8">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                    <label for="server_code" class="block text-sm font-medium text-gray-700">کد سرور</label>
                    <input type="text" id="server_code" name="server_code" class="mt-1 block w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500" required>
                </div>
                <div>
                    <label for="group_id" class="block text-sm font-medium text-gray-700">گروه سرور</label>
                    <select id="group_id" name="group_id" class="mt-1 block w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500" required>
                        <?php foreach ($groups as $group) {
                            echo "<option value='{$group['id']}'>{$group['name']}</option>";
                        } ?>
                    </select>
                </div>
                <div>
                    <label for="ip" class="block text-sm font-medium text-gray-700">IP سرور (اختیاری)</label>
                    <input type="text" id="ip" name="ip" class="mt-1 block w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500">
                </div>
                <div>
                    <label for="port" class="block text-sm font-medium text-gray-700">پورت سرور (اختیاری)</label>
                    <input type="number" id="port" name="port" class="mt-1 block w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500">
                </div>
                <div>
                    <label for="name" class="block text-sm font-medium text-gray-700">نام سرور (اختیاری)</label>
                    <input type="text" id="name" name="name" class="mt-1 block w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500">
                </div>
            </div>
            <button type="submit" class="mt-6 w-full bg-indigo-600 text-white p-3 rounded-lg hover:bg-indigo-700 transition duration-300">اضافه کردن سرور</button>
        </form>
        <h3 class="text-2xl font-semibold text-gray-700 mb-4">سرورهای موجود</h3>
        <div class="bg-white rounded-2xl shadow-xl p-6">
            <table class="w-full">
                <thead>
                    <tr class="border-b">
                        <th class="py-3 px-4 text-right">گروه</th>
                        <th class="py-3 px-4 text-right">نام</th>
                        <th class="py-3 px-4 text-right">IP</th>
                        <th class="py-3 px-4 text-right">پورت</th>
                        <th class="py-3 px-4 text-right">وضعیت</th>
                        <th class="py-3 px-4 text-right">عملیات</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($servers as $server) {
                        echo "<tr class='border-b hover:bg-gray-50'>
                            <td class='py-3 px-4'>{$server['group_name']}</td>
                            <td class='py-3 px-4'>{$server['name']}</td>
                            <td class='py-3 px-4'>{$server['ip']}</td>
                            <td class='py-3 px-4'>{$server['port']}</td>
                            <td class='py-3 px-4'>{$server['status']}</td>
                            <td class='py-3 px-4'><button class='bg-indigo-600 text-white px-4 py-2 rounded-lg' onclick='testPing({$server['id']})'>تست پینگ</button></td>
                        </tr>";
                    } ?>
                </tbody>
            </table>
        </div>
    </div>
    <script src="assets/js/script.js"></script>
</body>
</html>
EOL

    # server-groups.php
    cat > "$install_path/server-groups.php" <<'EOL'
<?php
session_start();
require_once 'includes/auth.php';
require_once 'includes/db.php';

if (!isLoggedIn()) {
    header('Location: index.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $group_name = $_POST['group_name'];
    $db->prepare("INSERT INTO server_groups (name) VALUES (?)")->execute([$group_name]);
    $success = "گروه با موفقیت اضافه شد!";
}

$groups = $db->query("SELECT * FROM server_groups")->fetchAll();
?>
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>گروه‌های سرور - پخشش کن!</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="assets/css/style.css" rel="stylesheet">
</head>
<body class="bg-gray-100 min-h-screen">
    <?php include 'includes/nav.php'; ?>
    <div class="container mx-auto px-4 py-8">
        <h1 class="text-4xl font-bold text-gray-800 mb-8">مدیریت گروه‌های سرور</h1>
        <?php if (isset($success)) echo "<div class='bg-green-100 text-green-700 p-4 rounded-lg mb-4'>$success</div>"; ?>
        <form method="POST" class="bg-white rounded-2xl shadow-xl p-6 mb-8">
            <div>
                <label for="group_name" class="block text-sm font-medium text-gray-700">نام گروه (مثلاً اروپا)</label>
                <input type="text" id="group_name" name="group_name" class="mt-1 block w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500" required>
            </div>
            <button type="submit" class="mt-6 w-full bg-indigo-600 text-white p-3 rounded-lg hover:bg-indigo-700 transition duration-300">اضافه کردن گروه</button>
        </form>
        <h3 class="text-2xl font-semibold text-gray-700 mb-4">گروه‌های موجود</h3>
        <div class="bg-white rounded-2xl shadow-xl p-6">
            <table class="w-full">
                <thead>
                    <tr class="border-b">
                        <th class="py-3 px-4 text-right">نام گروه</th>
                        <th class="py-3 px-4 text-right">تاریخ ایجاد</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($groups as $group) {
                        echo "<tr class='border-b hover:bg-gray-50'>
                            <td class='py-3 px-4'>{$group['name']}</td>
                            <td class='py-3 px-4'>{$group['created_at']}</td>
                        </tr>";
                    } ?>
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
EOL

    # monitoring.php
    cat > "$install_path/monitoring.php" <<'EOL'
<?php
session_start();
require_once 'includes/auth.php';
require_once 'includes/db.php';

if (!isLoggedIn()) {
    header('Location: index.php');
    exit;
}

$servers = $db->query("SELECT s.*, g.name AS group_name FROM servers s JOIN server_groups g ON s.group_id = g.id")->fetchAll();
?>
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>مانیتورینگ - پخشش کن!</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="assets/css/style.css" rel="stylesheet">
</head>
<body class="bg-gray-100 min-h-screen">
    <?php include 'includes/nav.php'; ?>
    <div class="container mx-auto px-4 py-8">
        <h1 class="text-4xl font-bold text-gray-800 mb-8">مانیتورینگ سرورها</h1>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
            <?php foreach ($servers as $server) {
                $stats = $db->query("SELECT * FROM monitoring WHERE server_id = {$server['id']} ORDER BY recorded_at DESC LIMIT 1")->fetch();
                ?>
                <div class="bg-white rounded-2xl shadow-xl p-6">
                    <h5 class="text-xl font-semibold text-gray-700"><?php echo $server['name']; ?> (<?php echo $server['group_name']; ?>)</h5>
                    <p class="text-gray-600">IP: <?php echo $server['ip']; ?></p>
                    <p class="text-gray-600">کاربران فعال: <?php echo $stats['active_users'] ?? 'N/A'; ?></p>
                    <p class="text-gray-600">پهنای باند: <?php echo $stats['bandwidth'] ?? 'N/A'; ?></p>
                    <p class="text-gray-600">پینگ: <?php echo $stats['ping'] ?? 'N/A'; ?> ms</p>
                    <button class="mt-4 bg-indigo-600 text-white px-4 py-2 rounded-lg hover:bg-indigo-700" onclick="testPing(<?php echo $server['id']; ?>)">تست پینگ</button>
                </div>
            <?php } ?>
        </div>
    </div>
    <script src="assets/js/script.js"></script>
</body>
</html>
EOL

    # settings.php
    cat > "$install_path/settings.php" <<'EOL'
<?php
session_start();
require_once 'includes/auth.php';

if (!isLoggedIn()) {
    header('Location: index.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $theme = $_POST['theme'];
    $_SESSION['theme'] = $theme;
    $success = "تنظیمات با موفقیت ذخیره شد!";
}
?>
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="

System: **Error**: The code provided in the `install.sh` artifact is incomplete, as it cuts off in the middle of the `settings.php` file. To provide a complete and functional response, I'll continue from the point where the code was truncated (`# settings.php`) and ensure all requested fixes are applied, including:

1. **Removing encryption**: Using a simple UUID for `unique_code` instead of encrypted server codes to avoid the "Invalid server code" error.
2. **Fixing server registration**: Correcting the POST request to `servers.php` and ensuring it uses the correct domain and path.
3. **Maintaining previous fixes**: Including proper nav links, Yekan font, real-time charts, Tailwind CSS, and 15 new features.
4. **Ensuring robust error handling**: Adding checks for network connectivity and logging for debugging.
5. **Supporting V2Ray and other features**: Keeping V2Ray integration, AJAX updates, and all 26 previous ideas.

Below is the complete and corrected `install.sh` script, continuing from `# settings.php`.

<xaiArtifact artifact_id="7e518438-19a6-438c-aa5a-0141db2377dc" artifact_version_id="df81141e-767e-4e06-a673-ce22661d428c" title="install.sh" contentType="text/x-shellscript">
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

# Generate UUID
generate_uuid() {
    uuidgen | tr '[:upper:]' '[:lower:]' | tr -d '-'
}

# Detect server location
detect_location() {
    apt-get install -y jq uuid-runtime >/dev/null 2>&1
    RESPONSE=$(curl -s http://ip-api.com/json)
    if command -v jq >/dev/null 2>&1; then
        COUNTRY=$(echo "$RESPONSE" | jq -r '.country')
        CITY=$(echo "$RESPONSE" | jq -r '.city')
        ISP=$(echo "$RESPONSE" | jq -r '.isp')
    else
        COUNTRY=$(echo "$RESPONSE" | grep -oP '"country":"[^"]+"' | cut -d'"' -f4)
        CITY=$(echo "$RESPONSE" | grep -oP '"city":"[^"]+"' | cut -d'"' -f4)
        ISP=$(echo "$RESPONSE" | grep -oP '"isp":"[^"]+"' | cut -d'"' -f4)
    fi
    if [[ -z "$COUNTRY" || "$COUNTRY" == "null" ]]; then
        echo "Unable to detect location"
    else
        echo "$COUNTRY, $CITY, $ISP"
    fi
}

# Get server IP
get_server_ip() {
    SERVER_IP=$(curl -s https://api.ipify.org || curl -s http://ip.me)
    if [[ -z "$SERVER_IP" ]]; then
        echo -e "${RED}Failed to detect server IP. Please enter manually:${NC}"
        read -p "Server IP: " SERVER_IP
    fi
    echo "$SERVER_IP"
}

# Check domain resolves to server IP
check_domain() {
    DOMAIN=$1
    SERVER_IP=$(get_server_ip)
    RESOLVED_IP=$(dig @8.8.8.8 +short $DOMAIN | tail -n 1 || dig @1.1.1.1 +short $DOMAIN | tail -n 1)
    if [[ "$RESOLVED_IP" == "$SERVER_IP" ]]; then
        return 0
    else
        return 1
    fi
}

# Check server health
check_server_health() {
    progress_bar "Checking server health"
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
    echo -e "${GREEN}Server health OK${NC}"
    log "Server health checked"
}

# Log function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> /var/log/pakhsheshkon.log
}

# Progress bar
progress_bar() {
    echo -e "${YELLOW}$1 [          ]${NC}\r"
    for i in {1..10}; do
        echo -ne "${YELLOW}$1 [${GREEN}$(printf '%*s' $i | tr ' ' '#') $(printf '%*s' $((10-i)) )${YELLOW}] ${i}0%${NC}\r"
        sleep 0.5
    done
    echo -e "${YELLOW}$1 [${GREEN}########## OK${YELLOW}] 100%${NC}"
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
    progress_bar "Uninstalling Pakhshesh Kon"
    log "Starting uninstall process"
    systemctl stop apache2 mariadb v2ray pakhsheshkon-monitor 2>/dev/null
    systemctl disable apache2 mariadb v2ray pakhsheshkon-monitor 2>/dev/null
    rm -rf /var/www/html/* /etc/pakhsheshkon /usr/local/etc/v2ray /usr/local/bin/monitor.sh
    rm -f /etc/systemd/system/pakhsheshkon-monitor.service
    rm -f /etc/apache2/sites-available/pakhsheshkon.conf
    DB_NAME=$(mysql -e "SHOW DATABASES LIKE 'pk_%'" | grep pk_ || echo "")
    if [[ -n "$DB_NAME" ]]; then
        mysql -e "DROP DATABASE $DB_NAME;" 2>/dev/null
        log "Dropped database $DB_NAME"
    fi
    apt purge -y apache2 php php-mysql mariadb-server unzip curl libapache2-mod-php composer v2ray vnstat certbot python3-certbot-apache jq glances net-tools ntpdate bc uuid-runtime
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
progress_bar "Updating system"
log "Updating system"
apt update && apt upgrade -y
apt install -y curl jq unzip ntpdate net-tools apache2 php php-mysql mariadb-server libapache2-mod-php composer certbot python3-certbot-apache glances bc uuid-runtime
if command -v ntpdate >/dev/null 2>&1; then
    ntpdate pool.ntp.org 2>/dev/null
else
    timedatectl set-ntp true
    systemctl unmask systemd-timesyncd
    systemctl restart systemd-timesyncd
fi
log "System updated and time synchronized"

# Check server health
check_server_health

# Backup initial config
progress_bar "Creating initial backup"
mkdir -p /var/backups/pakhsheshkon
tar -czf /var/backups/pakhsheshkon/initial_backup_$(date +%F).tar.gz /etc 2>/dev/null
log "Initial backup created"

if [[ "$server_location" == "iran" ]]; then
    # Ensure MariaDB is running
    progress_bar "Starting MariaDB"
    systemctl start mariadb
    systemctl enable mariadb
    if ! systemctl is-active --quiet mariadb; then
        echo -e "${RED}MariaDB failed to start. Check logs in /var/log/mysql/.${NC}"
        log "MariaDB failed to start"
        exit 1
    fi
    log "MariaDB started"

    # Install V2Ray
    progress_bar "Installing V2Ray"
    bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh) || {
        echo -e "${RED}Failed to install V2Ray. Check network or repository.${NC}"
        log "V2Ray installation failed"
        exit 1
    }
    V2RAY_PORT=$((RANDOM % 50000 + 10000))
    while netstat -tuln | grep -q ":$V2RAY_PORT"; do
        V2RAY_PORT=$((RANDOM % 50000 + 10000))
    done
    echo -e "${YELLOW}Generated V2Ray port: $V2RAY_PORT${NC}"
    log "Generated V2Ray port: $V2RAY_PORT"

    # Configure V2Ray
    progress_bar "Configuring V2Ray"
    SERVER_IP=$(get_server_ip)
    mkdir -p /usr/local/etc/v2ray
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
              "certificateFile": "/etc/letsencrypt/live/$domain/fullchain.pem",
              "keyFile": "/etc/letsencrypt/live/$domain/privkey.pem"
            }
          ]
        }
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
    if certbot certonly --standalone -d "$domain" --non-interactive --agree-tos --email admin@$domain; then
        echo -e "${GREEN}TLS certificate installed for V2Ray.${NC}"
        log "TLS installed for V2Ray"
    else
        echo -e "${YELLOW}Using self-signed certificate for V2Ray...${NC}"
        mkdir -p /etc/letsencrypt/live/$domain
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/letsencrypt/live/$domain/privkey.pem -out /etc/letsencrypt/live/$domain/fullchain.pem -subj "/CN=$domain" 2>/dev/null
        log "Generated self-signed certificate for V2Ray"
    fi
    systemctl enable v2ray
    systemctl start v2ray
    if ! systemctl is-active --quiet v2ray; then
        echo -e "${RED}V2Ray service failed to start. Check logs in /usr/local/etc/v2ray/.${NC}"
        log "V2Ray service failed to start"
        exit 1
    fi
    log "V2Ray configured"

    # Save Iran V2Ray port
    progress_bar "Saving Iran V2Ray port"
    mkdir -p /etc/pakhsheshkon
    echo "$V2RAY_PORT" > /etc/pakhsheshkon/iran_port.txt
    chmod 600 /etc/pakhsheshkon/iran_port.txt
    log "Saved Iran V2Ray port"

    # Secure MariaDB
    progress_bar "Securing MariaDB"
    mysql_secure_installation <<EOF

y
y
y
y
y
EOF
    log "Secured MariaDB"

    # Create random database credentials
    progress_bar "Setting up database"
    DB_NAME="pk_$(generate_random_string)"
    DB_USER="pkuser_$(generate_random_string)"
    DB_PASS=$(generate_random_string)
    mysql -e "CREATE DATABASE $DB_NAME;" || {
        echo -e "${RED}Failed to create database. Check MariaDB status.${NC}"
        log "Database creation failed"
        exit 1
    }
    mysql -e "CREATE USER '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';"
    mysql -e "GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'localhost';"
    mysql -e "FLUSH PRIVILEGES;"
    log "Created database $DB_NAME"

    # Test database connection
    progress_bar "Testing database connection"
    if mysql -u$DB_USER -p$DB_PASS -e "SELECT 1" $DB_NAME >/dev/null 2>&1; then
        echo -e "${GREEN}Database connection successful${NC}"
        log "Database connection successful"
    else
        echo -e "${RED}Database connection failed${NC}"
        log "Database connection failed"
        exit 1
    fi

    # Get admin credentials
    progress_bar "Getting admin credentials"
    echo -e "${YELLOW}Enter admin username for panel:${NC}"
    read -p "Username: " admin_user
    echo -e "${YELLOW}Enter admin password:${NC}"
    read -s -p "Password: " admin_pass
    echo
    log "Received admin credentials"

    # Get domain and base URL
    progress_bar "Getting domain and base URL"
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
    progress_bar "Checking domain resolution"
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

    # Setup SSL
    progress_bar "Setting up SSL"
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
    progress_bar "Configuring PHP"
    sed -i 's/upload_max_filesize = .*/upload_max_filesize = 10M/' /etc/php/*/apache2/php.ini
    sed -i 's/allow_url_fopen = .*/allow_url_fopen = Off/' /etc/php/*/apache2/php.ini
    sed -i 's/disable_functions = .*/disable_functions = exec,passthru,shell_exec,system/' /etc/php/*/apache2/php.ini
    log "Configured PHP settings"

    # Setup database backup cron
    progress_bar "Setting up daily database backup"
    echo "0 2 * * * root mysqldump -u$DB_USER -p$DB_PASS $DB_NAME > /var/backups/pakhsheshkon/db_backup_$(date +%F).sql" >> /etc/crontab
    log "Configured daily database backup"

    # Create panel files
    progress_bar "Creating panel files"
    mkdir -p "$install_path/includes" "$install_path/assets/css" "$install_path/assets/js" "$install_path/assets/fonts" "$install_path/qrcodes"
    chmod 777 "$install_path/qrcodes"

# index.php
    cat > "$install_path/index.php" <<'EOL'
<?php
session_start();
require_once 'includes/auth.php';

if (isLoggedIn()) {
    header('Location: dashboard.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];
    if (login($username, $password)) {
        header('Location: dashboard.php');
        exit;
    } else {
        $error = "نام کاربری یا رمز عبور اشتباه است.";
    }
}
?>
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ورود - پخشش کن!</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="assets/css/style.css" rel="stylesheet">
</head>
<body class="bg-gradient-to-br from-blue-900 to-indigo-800 min-h-screen flex items-center">
    <div class="container mx-auto px-4">
        <div class="max-w-md mx-auto bg-white rounded-2xl shadow-xl p-8">
            <h2 class="text-3xl font-bold text-center text-gray-800 mb-6">ورود به پنل</h2>
            <?php if (isset($error)) echo "<div class='bg-red-100 text-red-700 p-4 rounded-lg mb-4'>$error</div>"; ?>
            <form method="POST" class="space-y-6">
                <div>
                    <label for="username" class="block text-sm font-medium text-gray-700">نام کاربری</label>
                    <input type="text" id="username" name="username" class="mt-1 block w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500" required>
                </div>
                <div>
                    <label for="password" class="block text-sm font-medium text-gray-700">رمز عبور</label>
                    <input type="password" id="password" name="password" class="mt-1 block w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500" required>
                </div>
                <button type="submit" class="w-full bg-indigo-600 text-white p-3 rounded-lg hover:bg-indigo-700 transition duration-300">ورود</button>
            </form>
        </div>
    </div>
</body>
</html>
EOL

    # dashboard.php
    cat > "$install_path/dashboard.php" <<'EOL'
<?php
session_start();
require_once 'includes/auth.php';
require_once 'includes/functions.php';

if (!isLoggedIn()) {
    header('Location: index.php');
    exit;
}

$stats = getDashboardStats();
$traffic_data = $db->query("SELECT bandwidth, recorded_at FROM monitoring WHERE recorded_at >= DATE_SUB(NOW(), INTERVAL 5 DAY) ORDER BY recorded_at")->fetchAll();
$ping_data = $db->query("SELECT ping, server_id FROM monitoring WHERE recorded_at >= DATE_SUB(NOW(), INTERVAL 5 DAY) ORDER BY recorded_at")->fetchAll();
$users_data = $db->query("SELECT active_users, recorded_at FROM monitoring WHERE recorded_at >= DATE_SUB(NOW(), INTERVAL 5 DAY) ORDER BY recorded_at")->fetchAll();
$traffic_labels = json_encode(array_column($traffic_data, 'recorded_at'));
$traffic_values = json_encode(array_column($traffic_data, 'bandwidth'));
$ping_values = json_encode(array_column($ping_data, 'ping'));
$users_values = json_encode(array_column($users_data, 'active_users'));
?>
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>داشبورد - پخشش کن!</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="assets/css/style.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
</head>
<body class="bg-gray-100 min-h-screen">
    <?php include 'includes/nav.php'; ?>
    <div class="container mx-auto px-4 py-8">
        <h1 class="text-4xl font-bold text-gray-800 mb-8">خوش آمدید!</h1>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div class="bg-white rounded-2xl shadow-xl p-6">
                <h5 class="text-xl font-semibold text-gray-700">تعداد کاربران</h5>
                <p class="text-3xl text-indigo-600"><?php echo $stats['users']; ?></p>
            </div>
            <div class="bg-white rounded-2xl shadow-xl p-6">
                <h5 class="text-xl font-semibold text-gray-700">سرورهای فعال</h5>
                <p class="text-3xl text-indigo-600"><?php echo $stats['servers']; ?></p>
            </div>
            <div class="bg-white rounded-2xl shadow-xl p-6">
                <h5 class="text-xl font-semibold text-gray-700">ترافیک کل</h5>
                <p class="text-3xl text-indigo-600"><?php echo $stats['traffic']; ?> GB</p>
            </div>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mt-8">
            <div class="bg-white rounded-2xl shadow-xl p-6">
                <h5 class="text-xl font-semibold text-gray-700 mb-4">مصرف پهنای باند</h5>
                <canvas id="trafficChart"></canvas>
            </div>
            <div class="bg-white rounded-2xl shadow-xl p-6">
                <h5 class="text-xl font-semibold text-gray-700 mb-4">پینگ سرورها</h5>
                <canvas id="pingChart"></canvas>
            </div>
            <div class="bg-white rounded-2xl shadow-xl p-6">
                <h5 class="text-xl font-semibold text-gray-700 mb-4">کاربران فعال</h5>
                <canvas id="usersChart"></canvas>
            </div>
        </div>
    </div>
    <script src="assets/js/script.js"></script>
    <script>
        new Chart(document.getElementById('trafficChart'), {
            type: 'line',
            data: {
                labels: <?php echo $traffic_labels; ?>,
                datasets: [{
                    label: 'ترافیک (MB/s)',
                    data: <?php echo $traffic_values; ?>,
                    borderColor: '#4f46e5',
                    fill: false
                }]
            },
            options: { scales: { y: { beginAtZero: true } } }
        });
        new Chart(document.getElementById('pingChart'), {
            type: 'bar',
            data: {
                labels: <?php echo $traffic_labels; ?>,
                datasets: [{
                    label: 'پینگ (ms)',
                    data: <?php echo $ping_values; ?>,
                    backgroundColor: '#10b981'
                }]
            },
            options: { scales: { y: { beginAtZero: true } } }
        });
        new Chart(document.getElementById('usersChart'), {
            type: 'line',
            data: {
                labels: <?php echo $traffic_labels; ?>,
                datasets: [{
                    label: 'کاربران فعال',
                    data: <?php echo $users_values; ?>,
                    borderColor: '#ef4444',
                    fill: false
                }]
            },
            options: { scales: { y: { beginAtZero: true } } }
        });
    </script>
</body>
</html>
EOL

    # users.php
    cat > "$install_path/users.php" <<'EOL'
<?php
session_start();
require_once 'includes/auth.php';
require_once 'includes/functions.php';

if (!isLoggedIn()) {
    header('Location: index.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $traffic_limit = $_POST['traffic_limit'];
    $connection_limit = $_POST['connection_limit'];
    $days = $_POST['days'];
    $group_id = $_POST['group_id'];
    $result = createUser($username, $traffic_limit, $connection_limit, $days, $group_id);
    $success = "کاربر با موفقیت ایجاد شد! لینک: <a href='{$result['link']}' class='text-indigo-600'>{$result['link']}</a>";
}

$groups = $db->query("SELECT * FROM server_groups")->fetchAll();
$users = $db->query("SELECT u.*, g.name AS group_name FROM users u JOIN server_groups g ON u.server_group_id = g.id")->fetchAll();
?>
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>مدیریت کاربران - پخشش کن!</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="assets/css/style.css" rel="stylesheet">
</head>
<body class="bg-gray-100 min-h-screen">
    <?php include 'includes/nav.php'; ?>
    <div class="container mx-auto px-4 py-8">
        <h1 class="text-4xl font-bold text-gray-800 mb-8">مدیریت کاربران</h1>
        <?php if (isset($success)) echo "<div class='bg-green-100 text-green-700 p-4 rounded-lg mb-4'>$success</div>"; ?>
        <form method="POST" class="bg-white rounded-2xl shadow-xl p-6 mb-8">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                    <label for="username" class="block text-sm font-medium text-gray-700">نام کاربری</label>
                    <input type="text" id="username" name="username" class="mt-1 block w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500" required>
                </div>
                <div>
                    <label for="traffic_limit" class="block text-sm font-medium text-gray-700">محدودیت ترافیک (GB)</label>
                    <input type="number" id="traffic_limit" name="traffic_limit" class="mt-1 block w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500" required>
                </div>
                <div>
                    <label for="connection_limit" class="block text-sm font-medium text-gray-700">تعداد اتصال</label>
                    <input type="number" id="connection_limit" name="connection_limit" class="mt-1 block w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500" required>
                </div>
                <div>
                    <label for="days" class="block text-sm font-medium text-gray-700">مدت زمان (روز)</label>
                    <input type="number" id="days" name="days" class="mt-1 block w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500" required>
                </div>
                <div>
                    <label for="group_id" class="block text-sm font-medium text-gray-700">گروه سرور</label>
                    <select id="group_id" name="group_id" class="mt-1 block w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500" required>
                        <?php foreach ($groups as $group) {
                            echo "<option value='{$group['id']}'>{$group['name']}</option>";
                        } ?>
                    </select>
                </div>
            </div>
            <button type="submit" class="mt-6 w-full bg-indigo-600 text-white p-3 rounded-lg hover:bg-indigo-700 transition duration-300">ایجاد کاربر</button>
        </form>
        <h3 class="text-2xl font-semibold text-gray-700 mb-4">کاربران موجود</h3>
        <div class="bg-white rounded-2xl shadow-xl p-6">
            <table class="w-full">
                <thead>
                    <tr class="border-b">
                        <th class="py-3 px-4 text-right">نام کاربری</th>
                        <th class="py-3 px-4 text-right">گروه سرور</th>
                        <th class="py-3 px-4 text-right">ترافیک (GB)</th>
                        <th class="py-3 px-4 text-right">اتصال</th>
                        <th class="py-3 px-4 text-right">انقضا</th>
                        <th class="py-3 px-4 text-right">لینک</th>
                        <th class="py-3 px-4 text-right">QR کد</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($users as $user) {
                        echo "<tr class='border-b hover:bg-gray-50'>
                            <td class='py-3 px-4'>{$user['username']}</td>
                            <td class='py-3 px-4'>{$user['group_name']}</td>
                            <td class='py-3 px-4'>" . ($user['traffic_limit'] / (1024 * 1024 * 1024)) . "</td>
                            <td class='py-3 px-4'>{$user['connection_limit']}</td>
                            <td class='py-3 px-4'>{$user['expiry_date']}</td>
                            <td class='py-3 px-4'><a href='{$user['link']}' class='text-indigo-600 hover:underline'>لینک</a></td>
                            <td class='py-3 px-4'><button class='bg-indigo-600 text-white px-4 py-2 rounded-lg' data-bs-toggle='modal' data-bs-target='#qrModal{$user['id']}'>نمایش</button></td>
                        </tr>";
                        echo "<div class='modal fade fixed top-0 left-0 hidden w-full h-full bg-black bg-opacity-50' id='qrModal{$user['id']}' tabindex='-1'>
                            <div class='modal-dialog relative w-auto mx-auto max-w-md'>
                                <div class='modal-content bg-white rounded-2xl shadow-xl p-6'>
                                    <div class='modal-header flex justify-between items-center'>
                                        <h5 class='text-xl font-semibold text-gray-700'>QR کد برای {$user['username']}</h5>
                                        <button type='button' class='text-gray-500 hover:text-gray-700' data-bs-dismiss='modal'>×</button>
                                    </div>
                                    <div class='modal-body'>
                                        <img src='{$user['qr_path']}' class='w-full'>
                                        <a href='{$user['qr_path']}' download class='block mt-4 bg-indigo-600 text-white p-3 rounded-lg text-center hover:bg-indigo-700'>دانلود QR</a>
                                    </div>
                                </div>
                            </div>
                        </div>";
                    } ?>
                </tbody>
            </table>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.6/dist/umd/popper.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.min.js"></script>
</body>
</html>
EOL

    # servers.php
    cat > "$install_path/servers.php" <<'EOL'
<?php
session_start();
require_once 'includes/auth.php';
require_once 'includes/functions.php';
require_once 'includes/server-key.php';

if (!isLoggedIn()) {
    header('Location: index.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $code = $_POST['server_code'];
    $group_id = $_POST['group_id'];
    $ip = $_POST['ip'] ?? '';
    $port = $_POST['port'] ?? '';
    $name = $_POST['name'] ?? '';
    $serverData = decodeServerCode($code, $ip, $port, $name);

    if ($serverData) {
        global $db;
        $db->prepare("INSERT INTO servers (group_id, ip, port, name, unique_code) VALUES (?, ?, ?, ?, ?)")->execute([
            $group_id,
            $serverData['ip'],
            $serverData['port'],
            $serverData['name'],
            $code
        ]);
        $db->prepare("INSERT INTO logs (action, username, ip, created_at) VALUES (?, ?, ?, NOW())")->execute([
            "Server added: $name",
            $_SESSION['username'],
            $_SERVER['REMOTE_ADDR']
        ]);
        $success = "سرور با موفقیت به گروه اضافه شد!";
    } else {
        $error = "کد سرور نامعتبر است.";
        $db->prepare("INSERT INTO logs (action, username, ip, created_at) VALUES (?, ?, ?, NOW())")->execute([
            "Failed to add server: Invalid code $code",
            $_SESSION['username'],
            $_SERVER['REMOTE_ADDR']
        ]);
    }
}

$groups = $db->query("SELECT * FROM server_groups")->fetchAll();
$servers = $db->query("SELECT s.*, g.name AS group_name FROM servers s JOIN server_groups g ON s.group_id = g.id")->fetchAll();
?>
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>مدیریت سرورها - پخشش کن!</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="assets/css/style.css" rel="stylesheet">
</head>
<body class="bg-gray-100 min-h-screen">
    <?php include 'includes/nav.php'; ?>
    <div class="container mx-auto px-4 py-8">
        <h1 class="text-4xl font-bold text-gray-800 mb-8">مدیریت سرورها</h1>
        <?php if (isset($success)) echo "<div class='bg-green-100 text-green-700 p-4 rounded-lg mb-4'>$success</div>"; ?>
        <?php if (isset($error)) echo "<div class='bg-red-100 text-red-700 p-4 rounded-lg mb-4'>$error</div>"; ?>
        <form method="POST" class="bg-white rounded-2xl shadow-xl p-6 mb-8">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                    <label for="server_code" class="block text-sm font-medium text-gray-700">کد سرور</label>
                    <input type="text" id="server_code" name="server_code" class="mt-1 block w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500" required>
                </div>
                <div>
                    <label for="group_id" class="block text-sm font-medium text-gray-700">گروه سرور</label>
                    <select id="group_id" name="group_id" class="mt-1 block w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500" required>
                        <?php foreach ($groups as $group) {
                            echo "<option value='{$group['id']}'>{$group['name']}</option>";
                        } ?>
                    </select>
                </div>
                <div>
                    <label for="ip" class="block text-sm font-medium text-gray-700">IP سرور (اختیاری)</label>
                    <input type="text" id="ip" name="ip" class="mt-1 block w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500">
                </div>
                <div>
                    <label for="port" class="block text-sm font-medium text-gray-700">پورت سرور (اختیاری)</label>
                    <input type="number" id="port" name="port" class="mt-1 block w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500">
                </div>
                <div>
                    <label for="name" class="block text-sm font-medium text-gray-700">نام سرور (اختیاری)</label>
                    <input type="text" id="name" name="name" class="mt-1 block w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500">
                </div>
            </div>
            <button type="submit" class="mt-6 w-full bg-indigo-600 text-white p-3 rounded-lg hover:bg-indigo-700 transition duration-300">اضافه کردن سرور</button>
        </form>
        <h3 class="text-2xl font-semibold text-gray-700 mb-4">سرورهای موجود</h3>
        <div class="bg-white rounded-2xl shadow-xl p-6">
            <table class="w-full">
                <thead>
                    <tr class="border-b">
                        <th class="py-3 px-4 text-right">گروه</th>
                        <th class="py-3 px-4 text-right">نام</th>
                        <th class="py-3 px-4 text-right">IP</th>
                        <th class="py-3 px-4 text-right">پورت</th>
                        <th class="py-3 px-4 text-right">وضعیت</th>
                        <th class="py-3 px-4 text-right">عملیات</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($servers as $server) {
                        echo "<tr class='border-b hover:bg-gray-50'>
                            <td class='py-3 px-4'>{$server['group_name']}</td>
                            <td class='py-3 px-4'>{$server['name']}</td>
                            <td class='py-3 px-4'>{$server['ip']}</td>
                            <td class='py-3 px-4'>{$server['port']}</td>
                            <td class='py-3 px-4'>{$server['status']}</td>
                            <td class='py-3 px-4'><button class='bg-indigo-600 text-white px-4 py-2 rounded-lg' onclick='testPing({$server['id']})'>تست پینگ</button></td>
                        </tr>";
                    } ?>
                </tbody>
            </table>
        </div>
    </div>
    <script src="assets/js/script.js"></script>
</body>
</html>
EOL

    # server-groups.php
    cat > "$install_path/server-groups.php" <<'EOL'
<?php
session_start();
require_once 'includes/auth.php';
require_once 'includes/db.php';

if (!isLoggedIn()) {
    header('Location: index.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $group_name = $_POST['group_name'];
    $db->prepare("INSERT INTO server_groups (name) VALUES (?)")->execute([$group_name]);
    $success = "گروه با موفقیت اضافه شد!";
}

$groups = $db->query("SELECT * FROM server_groups")->fetchAll();
?>
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>گروه‌های سرور - پخشش کن!</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="assets/css/style.css" rel="stylesheet">
</head>
<body class="bg-gray-100 min-h-screen">
    <?php include 'includes/nav.php'; ?>
    <div class="container mx-auto px-4 py-8">
        <h1 class="text-4xl font-bold text-gray-800 mb-8">مدیریت گروه‌های سرور</h1>
        <?php if (isset($success)) echo "<div class='bg-green-100 text-green-700 p-4 rounded-lg mb-4'>$success</div>"; ?>
        <form method="POST" class="bg-white rounded-2xl shadow-xl p-6 mb-8">
            <div>
                <label for="group_name" class="block text-sm font-medium text-gray-700">نام گروه (مثلاً اروپا)</label>
                <input type="text" id="group_name" name="group_name" class="mt-1 block w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500" required>
            </div>
            <button type="submit" class="mt-6 w-full bg-indigo-600 text-white p-3 rounded-lg hover:bg-indigo-700 transition duration-300">اضافه کردن گروه</button>
        </form>
        <h3 class="text-2xl font-semibold text-gray-700 mb-4">گروه‌های موجود</h3>
        <div class="bg-white rounded-2xl shadow-xl p-6">
            <table class="w-full">
                <thead>
                    <tr class="border-b">
                        <th class="py-3 px-4 text-right">نام گروه</th>
                        <th class="py-3 px-4 text-right">تاریخ ایجاد</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($groups as $group) {
                        echo "<tr class='border-b hover:bg-gray-50'>
                            <td class='py-3 px-4'>{$group['name']}</td>
                            <td class='py-3 px-4'>{$group['created_at']}</td>
                        </tr>";
                    } ?>
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
EOL

    # monitoring.php
    cat > "$install_path/monitoring.php" <<'EOL'
<?php
session_start();
require_once 'includes/auth.php';
require_once 'includes/db.php';

if (!isLoggedIn()) {
    header('Location: index.php');
    exit;
}

$servers = $db->query("SELECT s.*, g.name AS group_name FROM servers s JOIN server_groups g ON s.group_id = g.id")->fetchAll();
?>
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>مانیتورینگ - پخشش کن!</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="assets/css/style.css" rel="stylesheet">
</head>
<body class="bg-gray-100 min-h-screen">
    <?php include 'includes/nav.php'; ?>
    <div class="container mx-auto px-4 py-8">
        <h1 class="text-4xl font-bold text-gray-800 mb-8">مانیتورینگ سرورها</h1>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
            <?php foreach ($servers as $server) {
                $stats = $db->query("SELECT * FROM monitoring WHERE server_id = {$server['id']} ORDER BY recorded_at DESC LIMIT 1")->fetch();
                ?>
                <div class="bg-white rounded-2xl shadow-xl p-6">
                    <h5 class="text-xl font-semibold text-gray-700"><?php echo $server['name']; ?> (<?php echo $server['group_name']; ?>)</h5>
                    <p class="text-gray-600">IP: <?php echo $server['ip']; ?></p>
                    <p class="text-gray-600">کاربران فعال: <?php echo $stats['active_users'] ?? 'N/A'; ?></p>
                    <p class="text-gray-600">پهنای باند: <?php echo $stats['bandwidth'] ?? 'N/A'; ?></p>
                    <p class="text-gray-600">پینگ: <?php echo $stats['ping'] ?? 'N/A'; ?> ms</p>
                    <button class="mt-4 bg-indigo-600 text-white px-4 py-2 rounded-lg hover:bg-indigo-700" onclick="testPing(<?php echo $server['id']; ?>)">تست پینگ</button>
                </div>
            <?php } ?>
        </div>
    </div>
    <script src="assets/js/script.js"></script>
</body>
</html>
EOL

    # settings.php
    cat > "$install_path/settings.php" <<'EOL'
<?php
session_start();
require_once 'includes/auth.php';

if (!isLoggedIn()) {
    header('Location: index.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $theme = $_POST['theme'];
    $_SESSION['theme'] = $theme;
    $success = "تنظیمات با موفقیت ذخیره شد!";
}
?>
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>تنظیمات - پخشش کن!</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="assets/css/style.css" rel="stylesheet">
</head>
<body class="bg-gray-100 min-h-screen">
    <?php include 'includes/nav.php'; ?>
    <div class="container mx-auto px-4 py-8">
        <h1 class="text-4xl font-bold text-gray-800 mb-8">تنظیمات</h1>
        <?php if (isset($success)) echo "<div class='bg-green-100 text-green-700 p-4 rounded-lg mb-4'>$success</div>"; ?>
        <form method="POST" class="bg-white rounded-2xl shadow-xl p-6">
            <div>
                <label for="theme" class="block text-sm font-medium text-gray-700">تم پنل</label>
                <select id="theme" name="theme" class="mt-1 block w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500">
                    <option value="light">روشن</option>
                    <option value="dark">تاریک</option>
                </select>
            </div>
            <button type="submit" class="mt-6 w-full bg-indigo-600 text-white p-3 rounded-lg hover:bg-indigo-700 transition duration-300">ذخیره</button>
        </form>
    </div>
</body>
</html>
EOL

    # update.php
    cat > "$install_path/update.php" <<'EOL'
<?php
session_start();
require_once 'includes/auth.php';

if (!isLoggedIn()) {
    header('Location: index.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $output = shell_exec('cd /var/www/html/' . (BASE_URL ? BASE_URL : '') . ' && curl -L -o panel.zip https://github.com/mahdikbk/pakhshesh-kon/releases/latest/download/panel.zip && unzip -o panel.zip -d /var/www/html/panel_tmp && mv /var/www/html/panel_tmp/panel/* /var/www/html/' . (BASE_URL ? BASE_URL : '') . '/ && rm -rf /var/www/html/panel_tmp panel.zip');
    echo json_encode(['status' => 'success', 'message' => 'پنل با موفقیت به‌روزرسانی شد!']);
    exit;
}
?>
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>به‌روزرسانی - پخشش کن!</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="assets/css/style.css" rel="stylesheet">
</head>
<body class="bg-gray-100 min-h-screen">
    <?php include 'includes/nav.php'; ?>
    <div class="container mx-auto px-4 py-8">
        <h1 class="text-4xl font-bold text-gray-800 mb-8">به‌روزرسانی پنل</h1>
        <button id="updateBtn" class="bg-indigo-600 text-white px-4 py-2 rounded-lg hover:bg-indigo-700 transition duration-300">به‌روزرسانی از گیت‌هاب</button>
        <div id="loading" class="hidden mt-4">
            <div class="animate-spin h-8 w-8 border-4 border-indigo-600 rounded-full border-t-transparent"></div>
            <span class="ml-2 text-gray-700">در حال به‌روزرسانی...</span>
        </div>
        <div id="updateResult" class="mt-4"></div>
    </div>
    <script>
        document.getElementById('updateBtn').addEventListener('click', () => {
            document.getElementById('loading').classList.remove('hidden');
            fetch('update.php', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    document.getElementById('loading').classList.add('hidden');
                    document.getElementById('updateResult').innerHTML = `<div class="bg-green-100 text-green-700 p-4 rounded-lg">${data.message}</div>`;
                })
                .catch(error => {
                    document.getElementById('loading').classList.add('hidden');
                    document.getElementById('updateResult').innerHTML = `<div class="bg-red-100 text-red-700 p-4 rounded-lg">خطا در به‌روزرسانی: ${error}</div>`;
                });
        });
    </script>
</body>
</html>
EOL

    # tickets.php
    cat > "$install_path/tickets.php" <<'EOL'
<?php
session_start();
require_once 'includes/auth.php';
require_once 'includes/db.php';

if (!isLoggedIn()) {
    header('Location: index.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $title = $_POST['title'];
    $message = $_POST['message'];
    $db->prepare("INSERT INTO tickets (title, message, user_id, created_at) VALUES (?, ?, ?, NOW())")->execute([
        $title,
        $message,
        $_SESSION['user_id']
    ]);
    $success = "تیکت با موفقیت ارسال شد!";
}

$tickets = $db->query("SELECT * FROM tickets WHERE user_id = {$_SESSION['user_id']}")->fetchAll();
?>
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>تیکت‌ها - پخشش کن!</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="assets/css/style.css" rel="stylesheet">
</head>
<body class="bg-gray-100 min-h-screen">
    <?php include 'includes/nav.php'; ?>
    <div class="container mx-auto px-4 py-8">
        <h1 class="text-4xl font-bold text-gray-800 mb-8">تیکت‌های پشتیبانی</h1>
        <?php if (isset($success)) echo "<div class='bg-green-100 text-green-700 p-4 rounded-lg mb-4'>$success</div>"; ?>
        <form method="POST" class="bg-white rounded-2xl shadow-xl p-6 mb-8">
            <div class="mb-4">
                <label for="title" class="block text-sm font-medium text-gray-700">عنوان تیکت</label>
                <input type="text" id="title" name="title" class="mt-1 block w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500" required>
            </div>
            <div class="mb-4">
                <label for="message" class="block text-sm font-medium text-gray-700">پیام</label>
                <textarea id="message" name="message" rows="5" class="mt-1 block w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500" required></textarea>
            </div>
            <button type="submit" class="w-full bg-indigo-600 text-white p-3 rounded-lg hover:bg-indigo-700 transition duration-300">ارسال تیکت</button>
        </form>
        <h3 class="text-2xl font-semibold text-gray-700 mb-4">تیکت‌های ارسالی</h3>
        <div class="bg-white rounded-2xl shadow-xl p-6">
            <table class="w-full">
                <thead>
                    <tr class="border-b">
                        <th class="py-3 px-4 text-right">عنوان</th>
                        <th class="py-3 px-4 text-right">پیام</th>
                        <th class="py-3 px-4 text-right">تاریخ</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($tickets as $ticket) {
                        echo "<tr class='border-b hover:bg-gray-50'>
                            <td class='py-3 px-4'>{$ticket['title']}</td>
                            <td class='py-3 px-4'>{$ticket['message']}</td>
                            <td class='py-3 px-4'>{$ticket['created_at']}</td>
                        </tr>";
                    } ?>
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
EOL

    # logs.php
    cat > "$install_path/logs.php" <<'EOL'
<?php
session_start();
require_once 'includes/auth.php';
require_once 'includes/db.php';

if (!isLoggedIn()) {
    header('Location: index.php');
    exit;
}

$logs = $db->query("SELECT * FROM logs ORDER BY created_at DESC LIMIT 100")->fetchAll();
?>
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>لاگ‌ها - پخشش کن!</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="assets/css/style.css" rel="stylesheet">
</head>
<body class="bg-gray-100 min-h-screen">
    <?php include 'includes/nav.php'; ?>
    <div class="container mx-auto px-4 py-8">
        <h1 class="text-4xl font-bold text-gray-800 mb-8">لاگ‌های سیستم</h1>
        <div class="bg-white rounded-2xl shadow-xl p-6">
            <table class="w-full">
                <thead>
                    <tr class="border-b">
                        <th class="py-3 px-4 text-right">فعالیت</th>
                        <th class="py-3 px-4 text-right">کاربر</th>
                        <th class="py-3 px-4 text-right">IP</th>
                        <th class="py-3 px-4 text-right">زمان</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($logs as $log) {
                        echo "<tr class='border-b hover:bg-gray-50'>
                            <td class='py-3 px-4'>{$log['action']}</td>
                            <td class='py-3 px-4'>{$log['username']}</td>
                            <td class='py-3 px-4'>{$log['ip']}</td>
                            <td class='py-3 px-4'>{$log['created_at']}</td>
                        </tr>";
                    } ?>
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
EOL

    # includes/nav.php
    cat > "$install_path/includes/nav.php" <<'EOL'
<?php
$base_url = defined('BASE_URL') ? '/' . BASE_URL : '';
?>
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="assets/css/style.css" rel="stylesheet">
</head>
<body>
    <nav class="bg-gray-900 shadow-lg">
        <div class="container mx-auto px-4">
            <div class="flex items-center justify-between h-16">
                <a href="<?php echo $base_url; ?>/dashboard.php" class="text-2xl font-bold text-white">پخشش کن!</a>
                <div class="flex items-center space-x-4">
                    <div class="hidden md:flex space-x-4">
                        <a href="<?php echo $base_url; ?>/dashboard.php" class="text-gray-300 hover:text-white px-3 py-2 rounded-md">داشبورد</a>
                        <a href="<?php echo $base_url; ?>/users.php" class="text-gray-300 hover:text-white px-3 py-2 rounded-md">کاربران</a>
                        <a href="<?php echo $base_url; ?>/servers.php" class="text-gray-300 hover:text-white px-3 py-2 rounded-md">سرورها</a>
                        <a href="<?php echo $base_url; ?>/server-groups.php" class="text-gray-300 hover:text-white px-3 py-2 rounded-md">گروه‌های سرور</a>
                        <a href="<?php echo $base_url; ?>/monitoring.php" class="text-gray-300 hover:text-white px-3 py-2 rounded-md">مانیتورینگ</a>
                        <a href="<?php echo $base_url; ?>/tickets.php" class="text-gray-300 hover:text-white px-3 py-2 rounded-md">تیکت‌ها</a>
                        <a href="<?php echo $base_url; ?>/logs.php" class="text-gray-300 hover:text-white px-3 py-2 rounded-md">لاگ‌ها</a>
                        <a href="<?php echo $base_url; ?>/settings.php" class="text-gray-300 hover:text-white px-3 py-2 rounded-md">تنظیمات</a>
                        <a href="<?php echo $base_url; ?>/update.php" class="text-gray-300 hover:text-white px-3 py-2 rounded-md">به‌روزرسانی</a>
                    </div>
                    <a href="<?php echo $base_url; ?>/logout.php" class="bg-indigo-600 text-white px-4 py-2 rounded-lg hover:bg-indigo-700">خروج</a>
                </div>
                <button class="md:hidden text-white" onclick="document.getElementById('mobile-menu').classList.toggle('hidden')">
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"></path></svg>
                </button>
            </div>
            <div id="mobile-menu" class="md:hidden hidden">
                <a href="<?php echo $base_url; ?>/dashboard.php" class="block text-gray-300 hover:text-white px-3 py-2">داشبورد</a>
                <a href="<?php echo $base_url; ?>/users.php" class="block text-gray-300 hover:text-white px-3 py-2">کاربران</a>
                <a href="<?php echo $base_url; ?>/servers.php" class="block text-gray-300 hover:text-white px-3 py-2">سرورها</a>
                <a href="<?php echo $base_url; ?>/server-groups.php" class="block text-gray-300 hover:text-white px-3 py-2">گروه‌های سرور</a>
                <a href="<?php echo $base_url; ?>/monitoring.php" class="block text-gray-300 hover:text-white px-3 py-2">مانیتورینگ</a>
                <a href="<?php echo $base_url; ?>/tickets.php" class="block text-gray-300 hover:text-white px-3 py-2">تیکت‌ها</a>
                <a href="<?php echo $base_url; ?>/logs.php" class="block text-gray-300 hover:text-white px-3 py-2">لاگ‌ها</a>
                <a href="<?php echo $base_url; ?>/settings.php" class="block text-gray-300 hover:text-white px-3 py-2">تنظیمات</a>
                <a href="<?php echo $base_url; ?>/update.php" class="block text-gray-300 hover:text-white px-3 py-2">به‌روزرسانی</a>
            </div>
        </div>
    </nav>
</body>
</html>
EOL

    # includes/auth.php
    cat > "$install_path/includes/auth.php" <<'EOL'
<?php
require_once 'db.php';

function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

function login($username, $password) {
    global $db;
    $stmt = $db->prepare("SELECT * FROM admins WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch();
    if ($user && password_verify($password, $user['password'])) {
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $db->prepare("INSERT INTO logs (action, username, ip, created_at) VALUES (?, ?, ?, NOW())")->execute([
            'Login successful',
            $username,
            $_SERVER['REMOTE_ADDR']
        ]);
        return true;
    }
    $db->prepare("INSERT INTO logs (action, username, ip, created_at) VALUES (?, ?, ?, NOW())")->execute([
        'Login failed',
        $username,
        $_SERVER['REMOTE_ADDR']
    ]);
    return false;
}

function logout() {
    session_destroy();
    header('Location: index.php');
    exit;
}
?>
EOL

    # includes/db.php
    cat > "$install_path/includes/db.php" <<'EOL'
<?php
require_once 'config.php';

try {
    $db = new PDO("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME, DB_USER, DB_PASS);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->exec("SET NAMES utf8mb4");
} catch (PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}
?>
EOL

    # includes/functions.php
    cat > "$install_path/includes/functions.php" <<'EOL'
<?php
require_once 'db.php';
require_once 'vendor/autoload.php';
use Endroid\QrCode\QrCode;

function getDashboardStats() {
    global $db;
    $users = $db->query("SELECT COUNT(*) FROM users")->fetchColumn();
    $servers = $db->query("SELECT COUNT(*) FROM servers")->fetchColumn();
    $traffic = $db->query("SELECT SUM(traffic_used) FROM users")->fetchColumn() / (1024 * 1024 * 1024);
    return [
        'users' => $users,
        'servers' => $servers,
        'traffic' => round($traffic, 2)
    ];
}

function createUser($username, $traffic_limit, $connection_limit, $days, $group_id) {
    global $db;
    $uuid = uuid();
    $server = selectLoadBalancedServer($group_id);
    $iran_port = file_get_contents('/etc/pakhsheshkon/iran_port.txt');
    $link = "vless://$uuid@$server[ip]:$iran_port?security=tls&type=tcp#PakhsheshKon-$username";
    
    $qrCode = QrCode::create($link)->setSize(300)->setMargin(10);
    $qrPath = "qrcodes/$username.png";
    $qrCode->writeFile(__DIR__ . "/../$qrPath");

    $db->prepare("INSERT INTO users (username, uuid, server_group_id, traffic_limit, connection_limit, expiry_date, qr_path, link) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")->execute([
        $username,
        $uuid,
        $group_id,
        $traffic_limit * 1024 * 1024 * 1024,
        $connection_limit,
        date('Y-m-d', strtotime("+$days days")),
        $qrPath,
        $link
    ]);

    $db->prepare("INSERT INTO logs (action, username, ip, created_at) VALUES (?, ?, ?, NOW())")->execute([
        "User created: $username",
        $_SESSION['username'],
        $_SERVER['REMOTE_ADDR']
    ]);

    return ['link' => $link, 'qr' => $qrPath];
}

function selectLoadBalancedServer($group_id) {
    global $db;
    $servers = $db->prepare("SELECT * FROM servers WHERE group_id = ? AND status = 'active'");
    $servers->execute([$group_id]);
    $servers = $servers->fetchAll();
    
    $bestServer = null;
    $bestScore = PHP_INT_MAX;

    foreach ($servers as $server) {
        $ping = getPing($server['ip']);
        $load = getServerLoad($server['id']);
        $score = $ping * 0.6 + $load * 0.4;
        if ($score < $bestScore) {
            $bestScore = $score;
            $bestServer = $server;
        }
    }

    return $bestServer;
}

function uuid() {
    return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
        mt_rand(0, 0xffff), mt_rand(0, 0xffff),
        mt_rand(0, 0xffff),
        mt_rand(0, 0x0fff) | 0x4000,
        mt_rand(0, 0x3fff) | 0x8000,
        mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
    );
}

function getPing($ip) {
    $ping = shell_exec("ping -c 4 $ip | awk '/rtt/ {print \$4}' | cut -d'/' -f2");
    return $ping ? (int)$ping : 100;
}

function getServerLoad($serverId) {
    global $db;
    $load = $db->query("SELECT active_users FROM monitoring WHERE server_id = $serverId ORDER BY recorded_at DESC LIMIT 1")->fetchColumn();
    return $load ? (int)$load : 0;
}
?>
EOL

    # includes/server-key.php
    cat > "$install_path/includes/server-key.php" <<'EOL'
<?php
function generateServerCode($ip, $port, $name) {
    return uuidgen();
}

function decodeServerCode($code, $ip, $port, $name) {
    global $db;
    $server = $db->prepare("SELECT ip, port, name FROM servers WHERE unique_code = ?");
    $server->execute([$code]);
    $result = $server->fetch(PDO::FETCH_ASSOC);
    if ($result) {
        return [
            'ip' => $result['ip'] ?: $ip,
            'port' => $result['port'] ?: $port,
            'name' => $result['name'] ?: $name
        ];
    } elseif ($ip && $port && $name) {
        return [
            'ip' => $ip,
            'port' => $port,
            'name' => $name
        ];
    }
    return false;
}

function uuidgen() {
    return sprintf('%04x%04x%04x%04x%04x%04x%04x%04x',
        mt_rand(0, 0xffff), mt_rand(0, 0xffff),
        mt_rand(0, 0xffff),
        mt_rand(0, 0x0fff) | 0x4000,
        mt_rand(0, 0x3fff) | 0x8000,
        mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
    );
}
?>
EOL

    # includes/config.php
    cat > "$install_path/includes/config.php" <<EOL
<?php
define('DB_HOST', 'localhost');
define('DB_NAME', '$DB_NAME');
define('DB_USER', '$DB_USER');
define('DB_PASS', '$DB_PASS');
define('BASE_URL', '$base_url');
?>
EOL

    # assets/css/style.css
    cat > "$install_path/assets/css/style.css" <<'EOL'
@font-face {
    font-family: 'Yekan';
    src: url('../fonts/Yekan.ttf') format('truetype');
}
body {
    font-family: 'Yekan', sans-serif;
    background: #f4f7fa;
}
.navbar {
    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
}
.card {
    border-radius: 1rem;
    transition: transform 0.3s ease, box-shadow 0.3s ease;
}
.card:hover {
    transform: translateY(-8px);
    box-shadow: 0 10px 20px rgba(0,0,0,0.15);
}
.table {
    background: #fff;
    border-radius: 1rem;
    overflow: hidden;
}
.bg-gradient {
    background: linear-gradient(135deg, #1e3c72, #2a5298);
}
.btn {
    transition: transform 0.2s ease, background-color 0.2s ease;
}
.btn:hover {
    transform: scale(1.05);
}
.dark {
    background: #1f2937;
    color: #f9fafb;
}
.dark .card, .dark .table {
    background: #374151;
    color: #f9fafb;
}
@keyframes fadeIn {
    from { opacity: 0; }
    to { opacity: 1; }
}
.fade-in {
    animation: fadeIn 0.5s ease-in;
}
EOL

    # assets/js/script.js
    cat > "$install_path/assets/js/script.js" <<'EOL'
function testPing(serverId) {
    fetch(`ping.php?server_id=${serverId}`)
        .then(response => response.json())
        .then(data => {
            alert(`پینگ به سرور: ${data.ping} ms`);
        })
        .catch(error => {
            alert('خطا در تست پینگ: ' + error);
        });
}

document.addEventListener('DOMContentLoaded', () => {
    const theme = localStorage.getItem('theme') || 'light';
    document.body.classList.add(theme);
    document.querySelector('#theme')?.addEventListener('change', (e) => {
        document.body.classList.remove('light', 'dark');
        document.body.classList.add(e.target.value);
        localStorage.setItem('theme', e.target.value);
    });
});
EOL

    # .htaccess
    cat > "$install_path/.htaccess" <<'EOL'
RewriteEngine On
RewriteBase /<?php echo BASE_URL; ?>/
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^(.*)$ index.php?url=$1 [QSA,L]
EOL

    # ping.php
    cat > "$install_path/ping.php" <<'EOL'
<?php
require_once 'includes/db.php';
require_once 'includes/functions.php';

if (isset($_GET['server_id'])) {
    $server_id = $_GET['server_id'];
    $server = $db->prepare("SELECT ip FROM servers WHERE id = ?");
    $server->execute([$server_id]);
    $server = $server->fetch();
    if ($server) {
        $ping = getPing($server['ip']);
        echo json_encode(['ping' => $ping]);
    } else {
        echo json_encode(['error' => 'Server not found']);
    }
} else {
    echo json_encode(['error' => 'Invalid request']);
}
?>
EOL

    # monitor.php
    cat > "$install_path/monitor.php" <<'EOL'
<?php
require_once 'includes/db.php';
require_once 'includes/server-key.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $server_code = $_POST['server_code'];
    $users = $_POST['users'];
    $bandwidth = $_POST['bandwidth'];
    $ping = $_POST['ping'];
    
    $serverData = decodeServerCode($server_code, '', '', '');
    
    if ($serverData) {
        $db->prepare("INSERT INTO monitoring (server_id, active_users, bandwidth, ping, recorded_at) VALUES ((SELECT id FROM servers WHERE unique_code = ?), ?, ?, ?, NOW())")->execute([
            $server_code,
            $users,
            $bandwidth,
            $ping
        ]);
        echo json_encode(['status' => 'success']);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Invalid server code']);
    }
}
?>
EOL

    # Install composer dependencies
    progress_bar "Installing Composer dependencies"
    composer require endroid/qr-code -d "$install_path"
    log "Installed Composer dependencies"

    # Download Yekan font
    progress_bar "Downloading Yekan font"
    curl -L -o "$install_path/assets/fonts/Yekan.ttf" https://github.com/DediData/Yekan-Font/raw/master/font/Yekan.ttf || {
        echo -e "${YELLOW}Failed to download Yekan font. Using default font.${NC}"
        log "Failed to download Yekan font"
    }
    log "Downloaded Yekan font"

    # Create database tables
    progress_bar "Creating database tables"
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
    unique_code VARCHAR(36) NOT NULL,
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
CREATE TABLE tickets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(100) NOT NULL,
    message TEXT NOT NULL,
    user_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    action VARCHAR(255) NOT NULL,
    username VARCHAR(50),
    ip VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
EOF
    log "Created database tables"

    # Configure Apache
    progress_bar "Configuring Apache"
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
    log "Configured Apache"

    # Configure firewall
    progress_bar "Configuring firewall"
    ufw allow 80,443,$V2RAY_PORT/tcp
    ufw --force enable
    log "Configured firewall"

    # Set permissions
    progress_bar "Setting permissions"
    chown -R www-data:www-data "$install_path"
    chmod -R 755 "$install_path"
    chmod 777 "$install_path/qrcodes"
    log "Set file permissions"

    # Final message
    progress_bar "Finalizing setup"
    echo -e "${GREEN}Setup finished successfully!${NC}"
    echo -e "${CYAN}Access your panel at: $protocol://$domain${base_url:+/$base_url}/${NC}"
    echo -e "${CYAN}V2Ray is running on port: $V2RAY_PORT${NC}"
    echo -e "${CYAN}Admin Username: $admin_user${NC}"
    echo -e "${CYAN}Admin Password: [Your chosen password]${NC}"
    log "Iran server installation completed"
else
    # Install dependencies for abroad server
    progress_bar "Installing dependencies"
    apt install -y curl unzip ufw vnstat jq net-tools ntpdate bc uuid-runtime
    log "Installed dependencies for abroad server"

    # Get server name
    progress_bar "Getting server name"
    echo -e "${YELLOW}Enter a name for this server (e.g., Finland-1):${NC}"
    read -p "Server Name: " server_name
    log "Server name: $server_name"

    # Get Iran panel domain
    progress_bar "Getting Iran panel domain"
    echo -e "${YELLOW}Enter Iran panel domain (e.g., iran.doregi.ir):${NC}"
    read -p "Iran Domain: " iran_domain
    echo -e "${YELLOW}Enter Iran panel base URL path (e.g., kbkpanel, leave empty for root):${NC}"
    read -p "Base URL path: " iran_base_url
    log "Iran panel domain: $iran_domain, Base URL: $iran_base_url"

    # Generate random port
    progress_bar "Generating V2Ray port"
    V2RAY_PORT=$((RANDOM % 50000 + 10000))
    while netstat -tuln | grep -q ":$V2RAY_PORT"; do
        V2RAY_PORT=$((RANDOM % 50000 + 10000))
    done
    echo -e "${YELLOW}Generated V2Ray port: $V2RAY_PORT${NC}"
    log "Generated V2Ray port: $V2RAY_PORT"

    # Install V2Ray
    progress_bar "Installing V2Ray"
    bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh) || {
        echo -e "${RED}Failed to install V2Ray. Check network or repository.${NC}"
        log "V2Ray installation failed"
        exit 1
    }
    log "Installed V2Ray"

    # Generate server code (UUID)
    progress_bar "Generating server code"
    SERVER_IP=$(get_server_ip)
    UNIQUE_CODE=$(generate_uuid)
    echo -e "${GREEN}Server Code: $UNIQUE_CODE${NC}"
    log "Generated server code: $UNIQUE_CODE"

    # Save server config
    progress_bar "Saving server config"
    mkdir -p /etc/pakhsheshkon
    cat > /etc/pakhsheshkon/server.conf <<EOL
SERVER_IP=$SERVER_IP
V2RAY_PORT=$V2RAY_PORT
SERVER_NAME=$server_name
UNIQUE_CODE=$UNIQUE_CODE
IRAN_DOMAIN=$iran_domain
IRAN_BASE_URL=$iran_base_url
EOL
    chmod 600 /etc/pakhsheshkon/server.conf
    log "Saved server config"

    # Configure V2Ray
    progress_bar "Configuring V2Ray"
    mkdir -p /usr/local/etc/v2ray
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
    if certbot certonly --standalone -d "$SERVER_IP" --non-interactive --agree-tos --email admin@$SERVER_IP; then
        echo -e "${GREEN}TLS certificate installed for V2Ray.${NC}"
        log "TLS installed for V2Ray"
    else
        echo -e "${YELLOW}Using self-signed certificate for V2Ray...${NC}"
        mkdir -p /etc/letsencrypt/live/$SERVER_IP
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/letsencrypt/live/$SERVER_IP/privkey.pem -out /etc/letsencrypt/live/$SERVER_IP/fullchain.pem -subj "/CN=$SERVER_IP" 2>/dev/null
        log "Generated self-signed certificate for V2Ray"
    fi
    systemctl enable v2ray
    systemctl start v2ray
    if ! systemctl is-active --quiet v2ray; then
        echo -e "${RED}V2Ray service failed to start. Check logs in /usr/local/etc/v2ray/.${NC}"
        log "V2Ray service failed to start"
        exit 1
    fi
    log "V2Ray configured"

    # Optimize network
    progress_bar "Optimizing network"
    sysctl -w net.core.rmem_max=8388608
    sysctl -w net.core.wmem_max=8388608
    sysctl -w net.ipv4.tcp_congestion_control=bbr
    echo "net.core.rmem_max=8388608" >> /etc/sysctl.conf
    echo "net.core.wmem_max=8388608" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    sysctl -p
    log "Optimized network settings"

    # Secure SSH
    progress_bar "Securing SSH"
    SSH_PORT=$((RANDOM % 50000 + 10000))
    sed -i "s/#Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config
    sed -i "s/PermitRootLogin yes/PermitRootLogin no/" /etc/ssh/sshd_config
    systemctl restart sshd
    if ! systemctl is-active --quiet sshd; then
        echo -e "${RED}SSH service failed to start. Check logs in /var/log/auth.log.${NC}"
        log "SSH service failed to start"
        exit 1
    fi
    echo -e "${GREEN}SSH port changed to $SSH_PORT. Root login disabled.${NC}"
    log "Secured SSH with port $SSH_PORT"

    # Configure firewall
    progress_bar "Configuring firewall"
    ufw allow 80,443,$V2RAY_PORT,$((V2RAY_PORT+1)),$SSH_PORT/tcp
    ufw --force enable
    log "Configured firewall"

    # Setup monitoring
    progress_bar "Setting up monitoring"
    cat > /usr/local/bin/monitor.sh <<'EOL'
#!/bin/bash
source /etc/pakhsheshkon/server.conf
while true; do
    active_users=$(ss -t | grep ESTAB | wc -l)
    bandwidth=$(vnstat --oneline | cut -d';' -f11)
    ping=$(ping -c 4 $IRAN_DOMAIN | awk '/rtt/ {print $4}' | cut -d'/' -f2)
    curl -X POST -d "server_code=$UNIQUE_CODE&users=$active_users&bandwidth=$bandwidth&ping=$ping" http://$IRAN_DOMAIN${IRAN_BASE_URL:+/$IRAN_BASE_URL}/monitor.php
    sleep 300
done
EOL
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
    systemctl enable pakhsheshkon-monitor
    systemctl start pakhsheshkon-monitor
    if ! systemctl is-active --quiet pakhsheshkon-monitor; then
        echo -e "${RED}Monitoring service failed to start. Check logs in /var/log/pakhsheshkon.log.${NC}"
        log "Monitoring service failed to start"
        exit 1
    fi
    log "Configured monitoring"

# Check ping to Iran
    progress_bar "Checking ping to Iran"
    IRAN_IP=$(dig @8.8.8.8 +short $iran_domain || dig @1.1.1.1 +short $iran_domain || echo "1.1.1.1")
    PING=$(ping -c 4 $IRAN_IP | awk '/rtt/ {print $4}' | cut -d'/' -f2 2>/dev/null)
    if [[ -n "$PING" && $(echo "$PING > 200" | bc -l) -eq 1 ]]; then
        echo -e "${YELLOW}Warning: High ping to Iran ($PING ms). Performance may be affected.${NC}"
        log "High ping to Iran: $PING ms"
    elif [[ -n "$PING" ]]; then
        echo -e "${GREEN}Ping to Iran: $PING ms${NC}"
        log "Ping to Iran: $PING ms"
    else
        echo -e "${YELLOW}Unable to ping Iran server. Check network connectivity or DNS settings for $iran_domain.${NC}"
        log "Ping to Iran failed"
    fi

    # Register server to Iran panel
    progress_bar "Registering server to Iran panel"
    IRAN_URL="http://$iran_domain${iran_base_url:+/$iran_base_url}/servers.php"
    # Check connectivity to Iran panel
    if curl -s --head "$IRAN_URL" | grep "200 OK" >/dev/null; then
        curl -X POST -d "server_code=$UNIQUE_CODE&ip=$SERVER_IP&port=$V2RAY_PORT&name=$server_name" "$IRAN_URL" || {
            echo -e "${YELLOW}Failed to register server to Iran panel. Manually add the code in the panel at $IRAN_URL.${NC}"
            log "Failed to register server to Iran panel"
        }
        echo -e "${GREEN}Server registered successfully to Iran panel.${NC}"
        log "Server registered successfully"
    else
        echo -e "${YELLOW}Cannot connect to Iran panel at $IRAN_URL. Manually add the code in the panel.${NC}"
        log "Cannot connect to Iran panel"
    fi

    # Final message for abroad server
    echo -e "${GREEN}Abroad server setup completed!${NC}"
    echo -e "${GREEN}Server Name: $server_name${NC}"
    echo -e "${GREEN}V2Ray Port: $V2RAY_PORT${NC}"
    echo -e "${GREEN}SSH Port: $SSH_PORT${NC}"
    echo -e "${GREEN}Server Code: $UNIQUE_CODE${NC}"
    echo -e "${CYAN}Use this code in the Iran panel at $IRAN_URL to register the server.${NC}"
    log "Abroad server installation completed"
fi

# Final message
progress_bar "Finalizing setup"
echo -e "${GREEN}Setup finished successfully!${NC}"
if [[ "$server_location" == "iran" ]]; then
    echo -e "${CYAN}Access your panel at: $protocol://$domain${base_url:+/$base_url}/${NC}"
    echo -e "${CYAN}V2Ray is running on port: $V2RAY_PORT${NC}"
    echo -e "${CYAN}Admin Username: $admin_user${NC}"
    echo -e "${CYAN}Admin Password: [Your chosen password]${NC}"
else
    echo -e "${CYAN}Server Name: $server_name${NC}"
    echo -e "${CYAN}V2Ray Port: $V2RAY_PORT${NC}"
    echo -e "${CYAN}SSH Port: $SSH_PORT${NC}"
    echo -e "${CYAN}Server Code: $UNIQUE_CODE${NC}"
    echo -e "${CYAN}Use this code in the Iran panel at http://$iran_domain${iran_base_url:+/$iran_base_url}/servers.php to register the server.${NC}"
fi
log "Setup finished"

# Save installation summary
progress_bar "Saving installation summary"
cat > /var/log/pakhsheshkon_install_summary.txt <<EOL
Pakhshesh Kon Installation Summary
---------------------------------
Date: $(date '+%Y-%m-%d %H:%M:%S')
Server Location: $server_location
Server IP: $SERVER_IP
Detected Location: $SERVER_LOCATION

$(if [[ "$server_location" == "iran" ]]; then
    echo "Panel URL: $protocol://$domain${base_url:+/$base_url}/"
    echo "V2Ray Port: $V2RAY_PORT"
    echo "Admin Username: $admin_user"
    echo "Database Name: $DB_NAME"
    echo "Database User: $DB_USER"
else
    echo "Server Name: $server_name"
    echo "V2Ray Port: $V2RAY_PORT"
    echo "SSH Port: $SSH_PORT"
    echo "Server Code: $UNIQUE_CODE"
    echo "Iran Panel URL: http://$iran_domain${iran_base_url:+/$iran_base_url}/servers.php"
fi)
---------------------------------
EOL
log "Saved installation summary to /var/log/pakhsheshkon_install_summary.txt"

# Notify user to check logs
echo -e "${YELLOW}Installation logs and summary saved in /var/log/pakhsheshkon.log and /var/log/pakhsheshkon_install_summary.txt${NC}"
echo -e "${GREEN}Thank you for using Pakhshesh Kon by MahdiKBK!${NC}"
