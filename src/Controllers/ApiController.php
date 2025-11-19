<?php

namespace PakhsheshKon\Controllers;

use PakhsheshKon\Core\Session;
use PakhsheshKon\Core\Security;
use PakhsheshKon\Core\Database;
use PakhsheshKon\Models\User;
use PakhsheshKon\Models\Server;
use PakhsheshKon\Models\Monitoring;
use PakhsheshKon\Services\TelegramService;

/**
 * کنترلر API RESTful
 */
class ApiController
{
    /**
     * ارسال JSON Response
     */
    private function json(array $data, int $statusCode = 200): void
    {
        http_response_code($statusCode);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        exit;
    }

    /**
     * بررسی احراز هویت API
     */
    private function checkAuth(): bool
    {
        $apiKey = $_SERVER['HTTP_X_API_KEY'] ?? $_GET['api_key'] ?? '';
        $validKey = getenv('API_KEY') ?: 'your-secret-api-key';
        
        return hash_equals($validKey, $apiKey);
    }

    /**
     * دریافت اطلاعات کاربر
     * GET /api/users/{id}
     */
    public function getUser(): void
    {
        if (!$this->checkAuth()) {
            $this->json(['error' => 'Unauthorized'], 401);
        }

        $id = (int)($_GET['id'] ?? 0);
        if (!$id) {
            $this->json(['error' => 'User ID required'], 400);
        }

        $user = User::findById($id);
        if (!$user) {
            $this->json(['error' => 'User not found'], 404);
        }

        $this->json([
            'id' => $user->getId(),
            'username' => $user->getUsername(),
            'uuid' => $user->getUUID(),
            'traffic_limit' => $user->getTrafficLimit(),
            'traffic_used' => $user->getTrafficUsed(),
            'expiry_date' => $user->getExpiryDate(),
            'is_expired' => $user->isExpired(),
            'has_traffic' => $user->hasTrafficLeft()
        ]);
    }

    /**
     * دریافت لیست کاربران
     * GET /api/users
     */
    public function getUsers(): void
    {
        if (!$this->checkAuth()) {
            $this->json(['error' => 'Unauthorized'], 401);
        }

        $limit = (int)($_GET['limit'] ?? 100);
        $offset = (int)($_GET['offset'] ?? 0);
        $groupId = $_GET['group_id'] ?? null;

        if ($groupId) {
            $users = User::findByGroup((int)$groupId);
        } else {
            $users = User::all($limit, $offset);
        }

        $result = array_map(function($user) {
            return [
                'id' => $user->getId(),
                'username' => $user->getUsername(),
                'uuid' => $user->getUUID(),
                'traffic_limit' => $user->getTrafficLimit(),
                'traffic_used' => $user->getTrafficUsed(),
                'expiry_date' => $user->getExpiryDate()
            ];
        }, $users);

        $this->json(['users' => $result, 'count' => count($result)]);
    }

    /**
     * ایجاد کاربر جدید
     * POST /api/users
     */
    public function createUser(): void
    {
        if (!$this->checkAuth()) {
            $this->json(['error' => 'Unauthorized'], 401);
        }

        $data = json_decode(file_get_contents('php://input'), true);
        
        $username = Security::sanitize($data['username'] ?? '');
        $trafficLimit = (int)($data['traffic_limit'] ?? 0);
        $connectionLimit = (int)($data['connection_limit'] ?? 1);
        $days = (int)($data['days'] ?? 30);
        $groupId = (int)($data['group_id'] ?? 1);

        if (empty($username) || !Security::validateUsername($username)) {
            $this->json(['error' => 'Invalid username'], 400);
        }

        if ($trafficLimit <= 0 || $connectionLimit <= 0 || $days <= 0) {
            $this->json(['error' => 'Invalid parameters'], 400);
        }

        try {
            $user = User::create($username, $trafficLimit, $connectionLimit, $days, $groupId);
            $this->json([
                'success' => true,
                'user' => [
                    'id' => $user->getId(),
                    'username' => $user->getUsername(),
                    'uuid' => $user->getUUID()
                ]
            ], 201);
        } catch (\Exception $e) {
            $this->json(['error' => $e->getMessage()], 500);
        }
    }

    /**
     * دریافت اطلاعات سرور
     * GET /api/servers/{id}
     */
    public function getServer(): void
    {
        if (!$this->checkAuth()) {
            $this->json(['error' => 'Unauthorized'], 401);
        }

        $id = (int)($_GET['id'] ?? 0);
        if (!$id) {
            $this->json(['error' => 'Server ID required'], 400);
        }

        $server = Server::findById($id);
        if (!$server) {
            $this->json(['error' => 'Server not found'], 404);
        }

        $latestMonitoring = Monitoring::getLatestByServer($id);

        $this->json([
            'id' => $server->getId(),
            'name' => $server->getName(),
            'ip' => $server->getIp(),
            'port' => $server->getPort(),
            'status' => $server->getStatus(),
            'monitoring' => $latestMonitoring ? [
                'active_users' => $latestMonitoring->getActiveUsers(),
                'bandwidth' => $latestMonitoring->getBandwidth(),
                'ping' => $latestMonitoring->getPing(),
                'recorded_at' => $latestMonitoring->getRecordedAt()
            ] : null
        ]);
    }

    /**
     * دریافت لیست سرورها
     * GET /api/servers
     */
    public function getServers(): void
    {
        if (!$this->checkAuth()) {
            $this->json(['error' => 'Unauthorized'], 401);
        }

        $servers = Server::all();
        $result = array_map(function($server) {
            return [
                'id' => $server->getId(),
                'name' => $server->getName(),
                'ip' => $server->getIp(),
                'port' => $server->getPort(),
                'status' => $server->getStatus()
            ];
        }, $servers);

        $this->json(['servers' => $result, 'count' => count($result)]);
    }

    /**
     * دریافت آمار داشبورد
     * GET /api/stats
     */
    public function getStats(): void
    {
        if (!$this->checkAuth()) {
            $this->json(['error' => 'Unauthorized'], 401);
        }

        $stats = [
            'users' => (int)Database::fetchColumn("SELECT COUNT(*) FROM users"),
            'active_users' => (int)Database::fetchColumn("SELECT COUNT(*) FROM users WHERE is_active = 1 AND expiry_date >= CURDATE()"),
            'servers' => (int)Database::fetchColumn("SELECT COUNT(*) FROM servers WHERE status = 'active'"),
            'total_traffic' => round((float)Database::fetchColumn("SELECT COALESCE(SUM(traffic_used), 0) FROM users") / (1024 * 1024 * 1024), 2),
            'expired_users' => (int)Database::fetchColumn("SELECT COUNT(*) FROM users WHERE expiry_date < CURDATE()"),
            'open_tickets' => (int)Database::fetchColumn("SELECT COUNT(*) FROM tickets WHERE status = 'open'")
        ];

        $this->json($stats);
    }

    /**
     * دریافت مانیتورینگ
     * GET /api/monitoring
     */
    public function getMonitoring(): void
    {
        if (!$this->checkAuth()) {
            $this->json(['error' => 'Unauthorized'], 401);
        }

        $serverId = $_GET['server_id'] ?? null;
        $days = (int)($_GET['days'] ?? 5);

        if ($serverId) {
            $data = Monitoring::getByServer((int)$serverId, $days);
        } else {
            $data = Monitoring::all(100);
        }

        $result = array_map(function($monitoring) {
            return [
                'id' => $monitoring->getId(),
                'server_id' => $monitoring->getServerId(),
                'active_users' => $monitoring->getActiveUsers(),
                'bandwidth' => $monitoring->getBandwidth(),
                'ping' => $monitoring->getPing(),
                'recorded_at' => $monitoring->getRecordedAt()
            ];
        }, $data);

        $this->json(['monitoring' => $result, 'count' => count($result)]);
    }

    /**
     * دریافت پینگ سرور
     * GET /api/ping
     */
    public function ping(): void
    {
        $serverId = (int)($_GET['server_id'] ?? 0);
        if (!$serverId) {
            $this->json(['error' => 'Server ID required'], 400);
        }

        $server = Server::findById($serverId);
        if (!$server) {
            $this->json(['error' => 'Server not found'], 404);
        }

        $ip = $server->getIp();
        $ping = $this->pingServer($ip);

        $this->json([
            'server_id' => $serverId,
            'ip' => $ip,
            'ping' => $ping,
            'status' => $ping > 0 ? 'online' : 'offline'
        ]);
    }

    /**
     * پینگ سرور
     */
    private function pingServer(string $ip): int
    {
        $command = "ping -c 4 {$ip} 2>&1";
        $output = shell_exec($command);
        
        if (preg_match('/rtt min\/avg\/max\/mdev = [\d.]+\/([\d.]+)\/[\d.]+\/[\d.]+/', $output, $matches)) {
            return (int)round((float)$matches[1]);
        }
        
        return -1;
    }
}

