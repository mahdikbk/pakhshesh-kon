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
    RESOLVED_IP=$(dig @8.8.8.8 +short $DOMAIN | tail -n 1)
    if [[ "$RESOLVED_IP" == "$SERVER_IP" ]]; then
        return 0
    else
        return 1
    fi
}

# Check server health
check_server_health() {
    echo -e "${YELLOW}Checking server health...${NC}"
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
}

# Log function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> /var/log/pakhsheshkon.log
}

# Progress bar
progress_bar() {
    echo -e "${YELLOW}$1 [          ]${NC}\r"
    for i in {1..10}; do
        echo -ne "${YELLOW}$1 [${GREEN}$(printf '%*s' $i | tr ' ' '#') $(printf '%*s' $((10-i)) )${YELLOW}]${NC}\r"
        sleep 0.5
    done
    echo -e "${YELLOW}$1 [${GREEN}########## OK${YELLOW}]${NC}"
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
progress_bar "Updating system"
log "Updating system"
apt update && apt upgrade -y
apt install -y curl jq unzip ntp apache2 php php-mysql mariadb-server libapache2-mod-php composer certbot python3-certbot-apache jq glances
ntpdate pool.ntp.org
log "System updated and NTP synchronized"

# Check server health
check_server_health
log "Server health checked"

# Backup initial config
progress_bar "Creating initial backup"
mkdir -p /var/backups/pakhsheshkon
tar -czf /var/backups/pakhsheshkon/initial_backup_$(date +%F).tar.gz /etc 2>/dev/null
log "Initial backup created"

if [[ "$server_location" == "iran" ]]; then
    # Install V2Ray for Iran server
    progress_bar "Installing V2Ray"
    bash <(curl -L https://github.com/v2fly/v2ray-core/releases/latest/download/install-release.sh)
    V2RAY_PORT=$((RANDOM % 50000 + 10000))
    while netstat -tuln | grep -q ":$V2RAY_PORT"; do
        V2RAY_PORT=$((RANDOM % 50000 + 10000))
    done
    echo -e "${YELLOW}Generated V2Ray port: $V2RAY_PORT${NC}"
    log "Generated V2Ray port: $V2RAY_PORT"

    # Configure V2Ray
    progress_bar "Configuring V2Ray"
    SERVER_IP=$(curl -s ifconfig.me)
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
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/pakhsheshkon/v2ray.key -out /etc/pakhsheshkon/v2ray.crt -subj "/CN=$SERVER_IP"
        mv /etc/pakhsheshkon/v2ray.crt /etc/letsencrypt/live/$SERVER_IP/fullchain.pem
        mv /etc/pakhsheshkon/v2ray.key /etc/letsencrypt/live/$SERVER_IP/privkey.pem
        log "Generated self-signed certificate for V2Ray"
    fi
    systemctl enable v2ray
    systemctl start v2ray
    log "V2Ray configured"

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
    mysql -e "CREATE DATABASE $DB_NAME;"
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
    <title>ورود - پخشش کن!</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="assets/css/style.css" rel="stylesheet">
</head>
<body class="bg-gradient bg-primary">
    <div class="container">
        <div class="row justify-content-center mt-5">
            <div class="col-md-4">
                <div class="card shadow">
                    <div class="card-body">
                        <h2 class="text-center mb-4">ورود به پنل</h2>
                        <?php if (isset($error)) echo "<div class='alert alert-danger'>$error</div>"; ?>
                        <form method="POST">
                            <div class="mb-3">
                                <label for="username" class="form-label">نام کاربری</label>
                                <input type="text" class="form-control" id="username" name="username" required>
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">رمز عبور</label>
                                <input type="password" class="form-control" id="password" name="password" required>
                            </div>
                            <button type="submit" class="btn btn-primary w-100">ورود</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
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
?>
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>داشبورد - پخشش کن!</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="assets/css/style.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
</head>
<body>
    <?php include 'includes/nav.php'; ?>
    <div class="container mt-4">
        <h1>خوش آمدید!</h1>
        <div class="row">
            <div class="col-md-4">
                <div class="card shadow">
                    <div class="card-body">
                        <h5 class="card-title">تعداد کاربران</h5>
                        <p class="card-text"><?php echo $stats['users']; ?></p>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card shadow">
                    <div class="card-body">
                        <h5 class="card-title">سرورهای فعال</h5>
                        <p class="card-text"><?php echo $stats['servers']; ?></p>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card shadow">
                    <div class="card-body">
                        <h5 class="card-title">ترافیک کل</h5>
                        <p class="card-text"><?php echo $stats['traffic']; ?> GB</p>
                    </div>
                </div>
            </div>
        </div>
        <div class="row mt-4">
            <div class="col-md-6">
                <div class="card shadow">
                    <div class="card-body">
                        <h5 class="card-title">مصرف پهنای باند</h5>
                        <canvas id="trafficChart"></canvas>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card shadow">
                    <div class="card-body">
                        <h5 class="card-title">پینگ سرورها</h5>
                        <canvas id="pingChart"></canvas>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="assets/js/script.js"></script>
    <script>
        new Chart(document.getElementById('trafficChart'), {
            type: 'line',
            data: {
                labels: ['روز 1', 'روز 2', 'روز 3', 'روز 4', 'روز 5'],
                datasets: [{
                    label: 'ترافیک (GB)',
                    data: [10, 20, 15, 25, 30],
                    borderColor: '#007bff',
                    fill: false
                }]
            }
        });
        new Chart(document.getElementById('pingChart'), {
            type: 'bar',
            data: {
                labels: ['سرور 1', 'سرور 2', 'سرور 3'],
                datasets: [{
                    label: 'پینگ (ms)',
                    data: [50, 30, 70],
                    backgroundColor: '#28a745'
                }]
            }
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
    $success = "کاربر با موفقیت ایجاد شد! لینک: <a href='{$result['link']}'>{$result['link']}</a>";
}

$groups = $db->query("SELECT * FROM server_groups")->fetchAll();
$users = $db->query("SELECT u.*, g.name AS group_name FROM users u JOIN server_groups g ON u.server_group_id = g.id")->fetchAll();
?>
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>مدیریت کاربران - پخشش کن!</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="assets/css/style.css" rel="stylesheet">
</head>
<body>
    <?php include 'includes/nav.php'; ?>
    <div class="container mt-4">
        <h1>مدیریت کاربران</h1>
        <?php if (isset($success)) echo "<div class='alert alert-success'>$success</div>"; ?>
        <form method="POST" class="mb-4">
            <div class="row">
                <div class="col-md-6 mb-3">
                    <label for="username" class="form-label">نام کاربری</label>
                    <input type="text" class="form-control" id="username" name="username" required>
                </div>
                <div class="col-md-6 mb-3">
                    <label for="traffic_limit" class="form-label">محدودیت ترافیک (GB)</label>
                    <input type="number" class="form-control" id="traffic_limit" name="traffic_limit" required>
                </div>
                <div class="col-md-6 mb-3">
                    <label for="connection_limit" class="form-label">تعداد اتصال</label>
                    <input type="number" class="form-control" id="connection_limit" name="connection_limit" required>
                </div>
                <div class="col-md-6 mb-3">
                    <label for="days" class="form-label">مدت زمان (روز)</label>
                    <input type="number" class="form-control" id="days" name="days" required>
                </div>
                <div class="col-md-6 mb-3">
                    <label for="group_id" class="form-label">گروه سرور</label>
                    <select class="form-control" id="group_id" name="group_id" required>
                        <?php foreach ($groups as $group) {
                            echo "<option value='{$group['id']}'>{$group['name']}</option>";
                        } ?>
                    </select>
                </div>
            </div>
            <button type="submit" class="btn btn-primary">ایجاد کاربر</button>
        </form>
        <h3>کاربران موجود</h3>
        <table class="table table-bordered table-hover">
            <thead>
                <tr>
                    <th>نام کاربری</th>
                    <th>گروه سرور</th>
                    <th>ترافیک (GB)</th>
                    <th>اتصال</th>
                    <th>انقضا</th>
                    <th>لینک</th>
                    <th>QR کد</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($users as $user) {
                    echo "<tr>
                        <td>{$user['username']}</td>
                        <td>{$user['group_name']}</td>
                        <td>" . ($user['traffic_limit'] / (1024 * 1024 * 1024)) . "</td>
                        <td>{$user['connection_limit']}</td>
                        <td>{$user['expiry_date']}</td>
                        <td><a href='{$user['link']}' class='btn btn-sm btn-link'>لینک</a></td>
                        <td><button class='btn btn-sm btn-info' data-bs-toggle='modal' data-bs-target='#qrModal{$user['id']}'>نمایش</button></td>
                    </tr>";
                    echo "<div class='modal fade' id='qrModal{$user['id']}' tabindex='-1'>
                        <div class='modal-dialog'>
                            <div class='modal-content'>
                                <div class='modal-header'>
                                    <h5 class='modal-title'>QR کد برای {$user['username']}</h5>
                                    <button type='button' class='btn-close' data-bs-dismiss='modal'></button>
                                </div>
                                <div class='modal-body'>
                                    <img src='{$user['qr_path']}' class='img-fluid'>
                                    <a href='{$user['qr_path']}' download class='btn btn-primary mt-2'>دانلود QR</a>
                                </div>
                            </div>
                        </div>
                    </div>";
                } ?>
            </tbody>
        </table>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
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
    $secretKey = SECRET_KEY;
    $serverData = decodeServerCode($code, $secretKey);

    if ($serverData) {
        global $db;
        $db->prepare("INSERT INTO servers (group_id, ip, port, name, unique_code) VALUES (?, ?, ?, ?, ?)")->execute([
            $group_id,
            $serverData['ip'],
            $serverData['port'],
            $serverData['name'],
            $code
        ]);
        $success = "سرور با موفقیت به گروه اضافه شد!";
    } else {
        $error = "کد سرور نامعتبر است.";
    }
}

$groups = $db->query("SELECT * FROM server_groups")->fetchAll();
$servers = $db->query("SELECT s.*, g.name AS group_name FROM servers s JOIN server_groups g ON s.group_id = g.id")->fetchAll();
?>
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>مدیریت سرورها - پخشش کن!</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="assets/css/style.css" rel="stylesheet">
</head>
<body>
    <?php include 'includes/nav.php'; ?>
    <div class="container mt-4">
        <h1>مدیریت سرورها</h1>
        <?php if (isset($success)) echo "<div class='alert alert-success'>$success</div>"; ?>
        <?php if (isset($error)) echo "<div class='alert alert-danger'>$error</div>"; ?>
        <form method="POST" class="mb-4">
            <div class="row">
                <div class="col-md-6 mb-3">
                    <label for="server_code" class="form-label">کد رمزنگاری‌شده سرور</label>
                    <input type="text" class="form-control" id="server_code" name="server_code" required>
                </div>
                <div class="col-md-6 mb-3">
                    <label for="group_id" class="form-label">گروه سرور</label>
                    <select class="form-control" id="group_id" name="group_id" required>
                        <?php foreach ($groups as $group) {
                            echo "<option value='{$group['id']}'>{$group['name']}</option>";
                        } ?>
                    </select>
                </div>
            </div>
            <button type="submit" class="btn btn-primary">اضافه کردن سرور</button>
        </form>
        <h3>سرورهای موجود</h3>
        <table class="table table-bordered table-hover">
            <thead>
                <tr>
                    <th>گروه</th>
                    <th>نام</th>
                    <th>IP</th>
                    <th>پورت</th>
                    <th>وضعیت</th>
                    <th>عملیات</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($servers as $server) {
                    echo "<tr>
                        <td>{$server['group_name']}</td>
                        <td>{$server['name']}</td>
                        <td>{$server['ip']}</td>
                        <td>{$server['port']}</td>
                        <td>{$server['status']}</td>
                        <td><button class='btn btn-sm btn-info' onclick='testPing({$server['id']})'>تست پینگ</button></td>
                    </tr>";
                } ?>
            </tbody>
        </table>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
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
    <title>گروه‌های سرور - پخشش کن!</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="assets/css/style.css" rel="stylesheet">
</head>
<body>
    <?php include 'includes/nav.php'; ?>
    <div class="container mt-4">
        <h1>مدیریت گروه‌های سرور</h1>
        <?php if (isset($success)) echo "<div class='alert alert-success'>$success</div>"; ?>
        <form method="POST" class="mb-4">
            <div class="mb-3">
                <label for="group_name" class="form-label">نام گروه (مثلاً اروپا)</label>
                <input type="text" class="form-control" id="group_name" name="group_name" required>
            </div>
            <button type="submit" class="btn btn-primary">اضافه کردن گروه</button>
        </form>
        <h3>گروه‌های موجود</h3>
        <table class="table table-bordered table-hover">
            <thead>
                <tr>
                    <th>نام گروه</th>
                    <th>تاریخ ایجاد</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($groups as $group) {
                    echo "<tr>
                        <td>{$group['name']}</td>
                        <td>{$group['created_at']}</td>
                    </tr>";
                } ?>
            </tbody>
        </table>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
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
    <title>مانیتورینگ - پخشش کن!</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="assets/css/style.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
</head>
<body>
    <?php include 'includes/nav.php'; ?>
    <div class="container mt-4">
        <h1>مانیتورینگ سرورها</h1>
        <div class="row">
            <?php foreach ($servers as $server) {
                $stats = $db->query("SELECT * FROM monitoring WHERE server_id = {$server['id']} ORDER BY recorded_at DESC LIMIT 1")->fetch();
                ?>
                <div class="col-md-4 mb-4">
                    <div class="card shadow">
                        <div class="card-body">
                            <h5 class="card-title"><?php echo $server['name']; ?> (<?php echo $server['group_name']; ?>)</h5>
                            <p>IP: <?php echo $server['ip']; ?></p>
                            <p>کاربران فعال: <?php echo $stats['active_users'] ?? 'N/A'; ?></p>
                            <p>پهنای باند: <?php echo $stats['bandwidth'] ?? 'N/A'; ?></p>
                            <p>پینگ: <?php echo $stats['ping'] ?? 'N/A'; ?> ms</p>
                            <button class="btn btn-sm btn-info" onclick="testPing(<?php echo $server['id']; ?>)">تست پینگ</button>
                        </div>
                    </div>
                </div>
            <?php } ?>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
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
    <title>تنظیمات - پخشش کن!</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="assets/css/style.css" rel="stylesheet">
</head>
<body>
    <?php include 'includes/nav.php'; ?>
    <div class="container mt-4">
        <h1>تنظیمات</h1>
        <?php if (isset($success)) echo "<div class='alert alert-success'>$success</div>"; ?>
        <form method="POST" class="mb-4">
            <div class="mb-3">
                <label for="theme" class="form-label">تم پنل</label>
                <select class="form-control" id="theme" name="theme">
                    <option value="light">روشن</option>
                    <option value="dark">تاریک</option>
                </select>
            </div>
            <button type="submit" class="btn btn-primary">ذخیره</button>
        </form>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
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
    <title>به‌روزرسانی - پخشش کن!</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="assets/css/style.css" rel="stylesheet">
</head>
<body>
    <?php include 'includes/nav.php'; ?>
    <div class="container mt-4">
        <h1>به‌روزرسانی پنل</h1>
        <button id="updateBtn" class="btn btn-primary">به‌روزرسانی از گیت‌هاب</button>
        <div id="loading" class="d-none mt-3">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">در حال به‌روزرسانی...</span>
            </div>
            <span>در حال به‌روزرسانی...</span>
        </div>
        <div id="updateResult" class="mt-3"></div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        document.getElementById('updateBtn').addEventListener('click', () => {
            document.getElementById('loading').classList.remove('d-none');
            fetch('update.php', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    document.getElementById('loading').classList.add('d-none');
                    document.getElementById('updateResult').innerHTML = `<div class="alert alert-success">${data.message}</div>`;
                })
                .catch(error => {
                    document.getElementById('loading').classList.add('d-none');
                    document.getElementById('updateResult').innerHTML = '<div class="alert alert-danger">خطا در به‌روزرسانی: ' + error + '</div>';
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
    <title>تیکت‌ها - پخشش کن!</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="assets/css/style.css" rel="stylesheet">
</head>
<body>
    <?php include 'includes/nav.php'; ?>
    <div class="container mt-4">
        <h1>تیکت‌های پشتیبانی</h1>
        <?php if (isset($success)) echo "<div class='alert alert-success'>$success</div>"; ?>
        <form method="POST" class="mb-4">
            <div class="mb-3">
                <label for="title" class="form-label">عنوان تیکت</label>
                <input type="text" class="form-control" id="title" name="title" required>
            </div>
            <div class="mb-3">
                <label for="message" class="form-label">پیام</label>
                <textarea class="form-control" id="message" name="message" rows="5" required></textarea>
            </div>
            <button type="submit" class="btn btn-primary">ارسال تیکت</button>
        </form>
        <h3>تیکت‌های ارسالی</h3>
        <table class="table table-bordered table-hover">
            <thead>
                <tr>
                    <th>عنوان</th>
                    <th>پیام</th>
                    <th>تاریخ</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($tickets as $ticket) {
                    echo "<tr>
                        <td>{$ticket['title']}</td>
                        <td>{$ticket['message']}</td>
                        <td>{$ticket['created_at']}</td>
                    </tr>";
                } ?>
            </tbody>
        </table>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
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
    <title>لاگ‌ها - پخشش کن!</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="assets/css/style.css" rel="stylesheet">
</head>
<body>
    <?php include 'includes/nav.php'; ?>
    <div class="container mt-4">
        <h1>لاگ‌های سیستم</h1>
        <table class="table table-bordered table-hover">
            <thead>
                <tr>
                    <th>فعالیت</th>
                    <th>کاربر</th>
                    <th>IP</th>
                    <th>زمان</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($logs as $log) {
                    echo "<tr>
                        <td>{$log['action']}</td>
                        <td>{$log['username']}</td>
                        <td>{$log['ip']}</td>
                        <td>{$log['created_at']}</td>
                    </tr>";
                } ?>
            </tbody>
        </table>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
EOL

    # includes/nav.php
    cat > "$install_path/includes/nav.php" <<'EOL'
<?php
$base_url = defined('BASE_URL') ? BASE_URL : '';
?>
<nav class="navbar navbar-expand-lg navbar-dark bg-dark shadow-sm">
    <div class="container">
        <a class="navbar-brand" href="<?php echo $base_url; ?>/dashboard.php">پخشش کن!</a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav me-auto">
                <li class="nav-item"><a class="nav-link" href="<?php echo $base_url; ?>/dashboard.php">داشبورد</a></li>
                <li class="nav-item"><a class="nav-link" href="<?php echo $base_url; ?>/users.php">کاربران</a></li>
                <li class="nav-item"><a class="nav-link" href="<?php echo $base_url; ?>/servers.php">سرورها</a></li>
                <li class="nav-item"><a class="nav-link" href="<?php echo $base_url; ?>/server-groups.php">گروه‌های سرور</a></li>
                <li class="nav-item"><a class="nav-link" href="<?php echo $base_url; ?>/monitoring.php">مانیتورینگ</a></li>
                <li class="nav-item"><a class="nav-link" href="<?php echo $base_url; ?>/tickets.php">تیکت‌ها</a></li>
                <li class="nav-item"><a class="nav-link" href="<?php echo $base_url; ?>/logs.php">لاگ‌ها</a></li>
                <li class="nav-item"><a class="nav-link" href="<?php echo $base_url; ?>/settings.php">تنظیمات</a></li>
                <li class="nav-item"><a class="nav-link" href="<?php echo $base_url; ?>/update.php">به‌روزرسانی</a></li>
            </ul>
            <a href="<?php echo $base_url; ?>/logout.php" class="btn btn-outline-light">خروج</a>
        </div>
    </div>
</nav>
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
    $iran_ip = $_SERVER['SERVER_ADDR'];
    $iran_port = file_get_contents('/etc/pakhsheshkon/iran_port.txt');
    $link = "vless://$uuid@$iran_ip:$iran_port?security=tls&type=tcp#PakhsheshKon-$username";
    
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
    return rand(10, 100); // Replace with real ping
}

function getServerLoad($serverId) {
    return rand(0, 100); // Replace with real load
}
?>
EOL

    # includes/server-key.php
    cat > "$install_path/includes/server-key.php" <<'EOL'
<?php
function generateServerCode($ip, $port, $name, $secretKey) {
    $data = "$ip|$port|$name";
    return hash_hmac('sha256', $data, $secretKey);
}

function decodeServerCode($code, $secretKey) {
    global $db;
    $server = $db->prepare("SELECT ip, port, name FROM servers WHERE unique_code = ?");
    $server->execute([$code]);
    $result = $server->fetch(PDO::FETCH_ASSOC);
    if ($result) {
        return [
            'ip' => $result['ip'],
            'port' => $result['port'],
            'name' => $result['name']
        ];
    }
    return false;
}
?>
EOL

    # includes/config.php
接待
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

    # assets/css/style.css
    cat > "$install_path/assets/css/style.css" <<'EOL'
@font-face {
    font-family: 'IRANSans';
    src: url('../fonts/iransans.ttf') format('truetype');
}
body {
    font-family: 'IRANSans', sans-serif;
    background: #f4f7fa;
}
.navbar {
    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
}
.card {
    border-radius: 10px;
    transition: transform 0.2s;
}
.card:hover {
    transform: translateY(-5px);
}
.table {
    background: #fff;
    border-radius: 10px;
}
.bg-gradient {
    background: linear-gradient(135deg, #1e3c72, #2a5298);
}
.btn {
    transition: all 0.3s;
}
.btn:hover {
    transform: scale(1.05);
}
.dark {
    background: #343a40;
    color: #fff;
}
.dark .card, .dark .table {
    background: #444;
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

    # Install composer dependencies
    progress_bar "Installing Composer dependencies"
    composer require endroid/qr-code -d "$install_path"
    log "Installed Composer dependencies"

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

    # Save Iran V2Ray port
    echo "$V2RAY_PORT" > /etc/pakhsheshkon/iran_port.txt
    log "Saved Iran V2Ray port"

    # Configure firewall
    progress_bar "Configuring firewall"
    ufw allow 80,443,$V2RAY_PORT/tcp
    ufw --force enable
    log "Configured firewall"

    # Set permissions
    progress_bar "Setting permissions"
    chown -R www-data:www-data "$install_path"
    chmod -R 755 "$install_path"
    log "Set file permissions"

    echo -e "${GREEN}Installation completed! Access panel at $protocol://$domain${base_url:+/$base_url}/${NC}"
    echo -e "${GREEN}Admin Username: $admin_user${NC}"
    echo -e "${GREEN}Admin Password: [Your chosen password]${NC}"
    log "Iran server installation completed"

else
    # Install dependencies for abroad server
    progress_bar "Installing dependencies"
    apt install -y curl unzip ufw vnstat jq
    log "Installed dependencies for abroad server"

    # Get server name
    progress_bar "Getting server name"
    echo -e "${YELLOW}Enter a name for this server (e.g., Finland-1):${NC}"
    read -p "Server Name: " server_name
    log "Server name: $server_name"

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
    bash <(curl -L https://github.com/v2fly/v2ray-core/releases/latest/download/install-release.sh)
    log "Installed V2Ray"

    # Generate encrypted server code
    progress_bar "Generating server code"
    SERVER_IP=$(curl -s ifconfig.me)
    SECRET_KEY=$(generate_random_string)
    SERVER_DATA=$(echo -n "$SERVER_IP|$V2RAY_PORT|$server_name")
    UNIQUE_CODE=$(echo -n "$SERVER_DATA" | openssl dgst -sha256 -hmac "$SECRET_KEY" | head -c 64)
    echo -e "${GREEN}Encrypted Server Code: $UNIQUE_CODE${NC}"
    log "Generated server code: $UNIQUE_CODE"

    # Save server config
    progress_bar "Saving server config"
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

    # Configure V2Ray
    progress_bar "Configuring V2Ray"
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
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/pakhsheshkon/v2ray.key -out /etc/pakhsheshkon/v2ray.crt -subj "/CN=$SERVER_IP"
        mv /etc/pakhsheshkon/v2ray.crt /etc/letsencrypt/live/$SERVER_IP/fullchain.pem
        mv /etc/pakhsheshkon/v2ray.key /etc/letsencrypt/live/$SERVER_IP/privkey.pem
        log "Generated self-signed certificate for V2Ray"
    fi
    log "Configured V2Ray"

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
    echo -e "${GREEN}SSH port changed to $SSH_PORT. Root login disabled.${NC}"
    log "Secured SSH with port $SSH_PORT"

    # Configure firewall
    progress_bar "Configuring firewall"
    ufw allow 80,443,$V2RAY_PORT,$((V2RAY_PORT+1)),$SSH_PORT/tcp
    ufw --force enable
    log "Configured firewall"

    # Setup monitoring
    progress_bar "Setting up monitoring"
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
    progress_bar "Checking ping to Iran"
    IRAN_IP=$(dig @8.8.8.8 +short iran.pakhsheshkon.com || echo "1.1.1.1")
    PING=$(ping -c 4 $IRAN_IP | awk '/rtt/ {print $4}' | cut -d'/' -f2 2>/dev/null)
    if [[ -n "$PING" && $(echo "$PING > 200" | bc -l) -eq 1 ]]; then
        echo -e "${YELLOW}Warning: High ping to Iran ($PING ms). Performance may be affected.${NC}"
        log "High ping to Iran: $PING ms"
    elif [[ -n "$PING" ]]; then
        echo -e "${GREEN}Ping to Iran: $PING ms${NC}"
        log "Ping to Iran: $PING ms"
    else
        echo -e "${YELLOW}Unable to ping Iran server. Check network connectivity.${NC}"
        log "Ping to Iran failed"
    fi

    # Finalize installation
    echo -e "${GREEN}Abroad server setup completed!${NC}"
    echo -e "${GREEN}Server Name: $server_name${NC}"
    echo -e "${GREEN}V2Ray Port: $V2RAY_PORT${NC}"
    echo -e "${GREEN}SSH Port: $SSH_PORT${NC}"
    echo -e "${GREEN}Use this encrypted code in Iran panel: $UNIQUE_CODE${NC}"
    log "Abroad server installation completed"
fi

# Final message
progress_bar "Finalizing setup"
echo -e "${GREEN}Setup finished successfully!${NC}"
if [[ "$server_location" == "iran" ]]; then
    echo -e "${CYAN}Access your panel at: $protocol://$domain${base_url:+/$base_url}/${NC}"
    echo -e "${CYAN}V2Ray is running on port: $V2RAY_PORT${NC}"
fi
log "Setup finished"
EOL
