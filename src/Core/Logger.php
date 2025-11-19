<?php

namespace PakhsheshKon\Core;

use PakhsheshKon\Core\Database;

/**
 * کلاس مدیریت لاگ
 */
class Logger
{
    private const LOG_LEVELS = [
        'DEBUG' => 0,
        'INFO' => 1,
        'WARNING' => 2,
        'ERROR' => 3,
        'CRITICAL' => 4
    ];

    /**
     * ثبت لاگ در دیتابیس
     */
    public static function log(
        string $action,
        ?string $username = null,
        ?string $ip = null,
        string $level = 'INFO'
    ): void {
        try {
            $ip = $ip ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';
            $username = $username ?? Session::get('username');
            
            Database::query(
                "INSERT INTO logs (action, username, ip, level, created_at) VALUES (?, ?, ?, ?, NOW())",
                [$action, $username, $ip, $level]
            );
        } catch (\Exception $e) {
            // اگر دیتابیس در دسترس نبود، در فایل لاگ کن
            error_log("Logger Error: " . $e->getMessage());
        }
    }

    /**
     * لاگ Debug
     */
    public static function debug(string $message, array $context = []): void
    {
        self::writeLog('DEBUG', $message, $context);
    }

    /**
     * لاگ Info
     */
    public static function info(string $message, array $context = []): void
    {
        self::writeLog('INFO', $message, $context);
    }

    /**
     * لاگ Warning
     */
    public static function warning(string $message, array $context = []): void
    {
        self::writeLog('WARNING', $message, $context);
    }

    /**
     * لاگ Error
     */
    public static function error(string $message, array $context = []): void
    {
        self::writeLog('ERROR', $message, $context);
    }

    /**
     * لاگ Critical
     */
    public static function critical(string $message, array $context = []): void
    {
        self::writeLog('CRITICAL', $message, $context);
    }

    /**
     * نوشتن لاگ در فایل
     */
    private static function writeLog(string $level, string $message, array $context = []): void
    {
        $logFile = dirname(__DIR__, 2) . '/logs/app.log';
        $logDir = dirname($logFile);
        
        if (!is_dir($logDir)) {
            mkdir($logDir, 0755, true);
        }
        
        $timestamp = date('Y-m-d H:i:s');
        $contextStr = !empty($context) ? ' ' . json_encode($context, JSON_UNESCAPED_UNICODE) : '';
        $logMessage = "[{$timestamp}] [{$level}] {$message}{$contextStr}" . PHP_EOL;
        
        file_put_contents($logFile, $logMessage, FILE_APPEND | LOCK_EX);
    }

    /**
     * دریافت لاگ‌ها از دیتابیس
     */
    public static function getLogs(int $limit = 100, int $offset = 0): array
    {
        return Database::fetchAll(
            "SELECT * FROM logs ORDER BY created_at DESC LIMIT ? OFFSET ?",
            [$limit, $offset]
        );
    }

    /**
     * پاک کردن لاگ‌های قدیمی
     */
    public static function cleanOldLogs(int $days = 30): int
    {
        return Database::query(
            "DELETE FROM logs WHERE created_at < DATE_SUB(NOW(), INTERVAL ? DAY)",
            [$days]
        )->rowCount();
    }
}

