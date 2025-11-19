<?php

namespace PakhsheshKon\Core;

/**
 * کلاس مدیریت تنظیمات
 */
class Config
{
    private static array $config = [];
    private static bool $loaded = false;

    /**
     * بارگذاری تنظیمات از فایل .env
     */
    public static function load(string $envPath = null): void
    {
        if (self::$loaded) {
            return;
        }

        $envPath = $envPath ?? dirname(__DIR__, 2) . '/.env';
        
        if (file_exists($envPath)) {
            $lines = file($envPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            foreach ($lines as $line) {
                if (strpos(trim($line), '#') === 0) {
                    continue;
                }
                
                list($name, $value) = explode('=', $line, 2);
                $name = trim($name);
                $value = trim($value);
                
                // حذف کوتیشن‌ها
                if (preg_match('/^"(.*)"$/', $value, $matches)) {
                    $value = $matches[1];
                } elseif (preg_match("/^'(.*)'$/", $value, $matches)) {
                    $value = $matches[1];
                }
                
                self::$config[$name] = $value;
            }
        }

        // تنظیمات پیش‌فرض
        self::$config = array_merge([
            'DB_HOST' => 'localhost',
            'DB_NAME' => 'pakhshesh_kon',
            'DB_USER' => 'root',
            'DB_PASS' => '',
            'APP_ENV' => 'production',
            'APP_DEBUG' => 'false',
            'APP_URL' => 'http://localhost',
            'BASE_URL' => '',
            'CSRF_SECRET' => bin2hex(random_bytes(32)),
            'SESSION_LIFETIME' => 3600,
            'RATE_LIMIT_ENABLED' => 'true',
            'RATE_LIMIT_MAX_ATTEMPTS' => '5',
            'RATE_LIMIT_WINDOW' => '300',
            'TELEGRAM_ENABLED' => 'false',
            'BACKUP_ENABLED' => 'true',
            'BACKUP_PATH' => '/var/backups/pakhsheshkon',
            'MONITORING_INTERVAL' => '300',
        ], self::$config);

        self::$loaded = true;
    }

    /**
     * دریافت مقدار تنظیمات
     */
    public static function get(string $key, $default = null)
    {
        if (!self::$loaded) {
            self::load();
        }
        
        return self::$config[$key] ?? $default;
    }

    /**
     * تنظیم مقدار
     */
    public static function set(string $key, $value): void
    {
        self::$config[$key] = $value;
    }

    /**
     * بررسی وجود کلید
     */
    public static function has(string $key): bool
    {
        if (!self::$loaded) {
            self::load();
        }
        
        return isset(self::$config[$key]);
    }

    /**
     * دریافت تمام تنظیمات
     */
    public static function all(): array
    {
        if (!self::$loaded) {
            self::load();
        }
        
        return self::$config;
    }
}

