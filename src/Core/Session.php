<?php

namespace PakhsheshKon\Core;

/**
 * کلاس مدیریت Session
 */
class Session
{
    private static bool $started = false;

    /**
     * شروع Session
     */
    public static function start(): void
    {
        if (self::$started) {
            return;
        }

        // تنظیمات امنیتی Session
        ini_set('session.cookie_httponly', '1');
        ini_set('session.cookie_secure', self::isHTTPS() ? '1' : '0');
        ini_set('session.cookie_samesite', 'Strict');
        ini_set('session.use_strict_mode', '1');
        
        $lifetime = (int)Config::get('SESSION_LIFETIME', 3600);
        ini_set('session.gc_maxlifetime', $lifetime);
        ini_set('session.cookie_lifetime', $lifetime);

        session_start();
        self::$started = true;

        // Regenerate ID برای امنیت بیشتر
        if (!isset($_SESSION['created'])) {
            session_regenerate_id(true);
            $_SESSION['created'] = time();
        } elseif (time() - $_SESSION['created'] > 1800) {
            // Regenerate هر 30 دقیقه
            session_regenerate_id(true);
            $_SESSION['created'] = time();
        }
    }

    /**
     * دریافت مقدار
     */
    public static function get(string $key, $default = null)
    {
        self::start();
        return $_SESSION[$key] ?? $default;
    }

    /**
     * تنظیم مقدار
     */
    public static function set(string $key, $value): void
    {
        self::start();
        $_SESSION[$key] = $value;
    }

    /**
     * حذف مقدار
     */
    public static function delete(string $key): void
    {
        self::start();
        unset($_SESSION[$key]);
    }

    /**
     * بررسی وجود کلید
     */
    public static function has(string $key): bool
    {
        self::start();
        return isset($_SESSION[$key]);
    }

    /**
     * حذف تمام Session
     */
    public static function destroy(): void
    {
        self::start();
        $_SESSION = [];
        
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(
                session_name(),
                '',
                time() - 42000,
                $params["path"],
                $params["domain"],
                $params["secure"],
                $params["httponly"]
            );
        }
        
        session_destroy();
        self::$started = false;
    }

    /**
     * Flash Message
     */
    public static function flash(string $key, $value = null)
    {
        self::start();
        
        if ($value === null) {
            // دریافت و حذف
            $message = $_SESSION['_flash'][$key] ?? null;
            unset($_SESSION['_flash'][$key]);
            return $message;
        }
        
        // تنظیم
        if (!isset($_SESSION['_flash'])) {
            $_SESSION['_flash'] = [];
        }
        $_SESSION['_flash'][$key] = $value;
    }

    /**
     * بررسی HTTPS
     */
    private static function isHTTPS(): bool
    {
        return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ||
               $_SERVER['SERVER_PORT'] == 443 ||
               (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
    }
}

