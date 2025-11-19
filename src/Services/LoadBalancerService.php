<?php

namespace PakhsheshKon\Services;

use PakhsheshKon\Models\Server;
use PakhsheshKon\Models\Monitoring;

/**
 * سرویس توزیع بار (Load Balancing)
 */
class LoadBalancerService
{
    /**
     * انتخاب بهترین سرور بر اساس الگوریتم
     */
    public static function selectBestServer(int $groupId, string $algorithm = 'weighted'): ?Server
    {
        $servers = Server::findByGroup($groupId);
        
        if (empty($servers)) {
            return null;
        }

        switch ($algorithm) {
            case 'round_robin':
                return self::roundRobin($servers);
            
            case 'least_connections':
                return self::leastConnections($servers);
            
            case 'weighted':
            default:
                return self::weighted($servers);
        }
    }

    /**
     * الگوریتم Round Robin
     */
    private static function roundRobin(array $servers): Server
    {
        static $index = 0;
        $server = $servers[$index % count($servers)];
        $index++;
        return $server;
    }

    /**
     * الگوریتم Least Connections
     */
    private static function leastConnections(array $servers): Server
    {
        $bestServer = null;
        $minConnections = PHP_INT_MAX;

        foreach ($servers as $server) {
            $monitoring = Monitoring::getLatestByServer($server->getId());
            $connections = $monitoring ? $monitoring->getActiveUsers() : 0;

            if ($connections < $minConnections) {
                $minConnections = $connections;
                $bestServer = $server;
            }
        }

        return $bestServer ?? $servers[0];
    }

    /**
     * الگوریتم Weighted (پینگ + بار)
     */
    private static function weighted(array $servers): Server
    {
        $bestServer = null;
        $bestScore = PHP_INT_MAX;

        foreach ($servers as $server) {
            $monitoring = Monitoring::getLatestByServer($server->getId());
            
            $ping = $monitoring ? $monitoring->getPing() : 100;
            $load = $monitoring ? $monitoring->getActiveUsers() : 0;

            // نمره = پینگ * 0.6 + بار * 0.4
            $score = ($ping * 0.6) + ($load * 0.4);

            if ($score < $bestScore) {
                $bestScore = $score;
                $bestServer = $server;
            }
        }

        return $bestServer ?? $servers[0];
    }

    /**
     * بررسی سلامت سرور
     */
    public static function checkServerHealth(Server $server): array
    {
        $monitoring = Monitoring::getLatestByServer($server->getId());
        
        $health = [
            'status' => 'unknown',
            'ping' => -1,
            'active_users' => 0,
            'uptime' => 0
        ];

        if ($monitoring) {
            $ping = $monitoring->getPing();
            $health['ping'] = $ping ?? -1;
            $health['active_users'] = $monitoring->getActiveUsers() ?? 0;
            
            if ($ping !== null && $ping > 0 && $ping < 1000) {
                $health['status'] = 'healthy';
            } elseif ($ping !== null && $ping >= 1000) {
                $health['status'] = 'slow';
            } else {
                $health['status'] = 'offline';
            }
        } else {
            $health['status'] = 'no_data';
        }

        return $health;
    }

    /**
     * دریافت آمار توزیع بار
     */
    public static function getLoadStats(int $groupId): array
    {
        $servers = Server::findByGroup($groupId);
        $stats = [];

        foreach ($servers as $server) {
            $monitoring = Monitoring::getLatestByServer($server->getId());
            $health = self::checkServerHealth($server);

            $stats[] = [
                'server_id' => $server->getId(),
                'server_name' => $server->getName(),
                'ip' => $server->getIp(),
                'status' => $health['status'],
                'ping' => $health['ping'],
                'active_users' => $health['active_users'],
                'load_percentage' => self::calculateLoadPercentage($server)
            ];
        }

        return $stats;
    }

    /**
     * محاسبه درصد بار
     */
    private static function calculateLoadPercentage(Server $server): float
    {
        $monitoring = Monitoring::getLatestByServer($server->getId());
        if (!$monitoring) {
            return 0;
        }

        $activeUsers = $monitoring->getActiveUsers() ?? 0;
        // فرض: حداکثر 100 کاربر = 100%
        $maxCapacity = 100;
        
        return min(100, ($activeUsers / $maxCapacity) * 100);
    }
}

