<?php

namespace PakhsheshKon\Controllers;

use PakhsheshKon\Core\Session;
use PakhsheshKon\Core\Database;
use PakhsheshKon\Core\Security;

/**
 * کنترلر داشبورد
 */
class DashboardController
{
    /**
     * صفحه اصلی داشبورد
     */
    public function index(): void
    {
        // بررسی لاگین
        if (!Session::has('user_id')) {
            header('Location: /login');
            exit;
        }

        // آمار کلی
        $stats = [
            'users' => (int)Database::fetchColumn("SELECT COUNT(*) FROM users"),
            'servers' => (int)Database::fetchColumn("SELECT COUNT(*) FROM servers WHERE status = 'active'"),
            'traffic' => round((float)Database::fetchColumn("SELECT COALESCE(SUM(traffic_used), 0) FROM users") / (1024 * 1024 * 1024), 2),
            'active_servers' => (int)Database::fetchColumn("SELECT COUNT(DISTINCT server_id) FROM monitoring WHERE recorded_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)")
        ];

        // داده‌های نمودار (5 روز گذشته)
        $trafficData = Database::fetchAll(
            "SELECT bandwidth, recorded_at 
             FROM monitoring 
             WHERE recorded_at >= DATE_SUB(NOW(), INTERVAL 5 DAY) 
             ORDER BY recorded_at"
        );

        $pingData = Database::fetchAll(
            "SELECT ping, server_id, recorded_at 
             FROM monitoring 
             WHERE recorded_at >= DATE_SUB(NOW(), INTERVAL 5 DAY) 
             ORDER BY recorded_at"
        );

        $usersData = Database::fetchAll(
            "SELECT active_users, recorded_at 
             FROM monitoring 
             WHERE recorded_at >= DATE_SUB(NOW(), INTERVAL 5 DAY) 
             ORDER BY recorded_at"
        );

        // آماده‌سازی داده‌ها برای Chart.js
        $trafficLabels = json_encode(array_column($trafficData, 'recorded_at'));
        $trafficValues = json_encode(array_column($trafficData, 'bandwidth'));
        $pingValues = json_encode(array_column($pingData, 'ping'));
        $usersValues = json_encode(array_column($usersData, 'active_users'));

        $csrfToken = Security::generateCSRFToken();
        require dirname(__DIR__, 2) . '/views/dashboard/index.php';
    }
}

