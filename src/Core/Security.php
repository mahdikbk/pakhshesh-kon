<?php

namespace PakhsheshKon\Core;

/**
 * کلاس مدیریت امنیت
 */
class Security
{
    /**
     * تولید CSRF Token
     */
    public static function generateCSRFToken(): string
    {
        if (!isset($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            $_SESSION['csrf_token_time'] = time();
        }
        
        return $_SESSION['csrf_token'];
    }

    /**
     * بررسی CSRF Token
     */
    public static function validateCSRFToken(?string $token): bool
    {
        if (!isset($_SESSION['csrf_token'])) {
            return false;
        }
        
        // بررسی انقضا (15 دقیقه)
        if (isset($_SESSION['csrf_token_time']) && 
            (time() - $_SESSION['csrf_token_time']) > 900) {
            unset($_SESSION['csrf_token'], $_SESSION['csrf_token_time']);
            return false;
        }
        
        return hash_equals($_SESSION['csrf_token'], $token ?? '');
    }

    /**
     * Sanitize Input
     */
    public static function sanitize($input, int $flags = ENT_QUOTES, string $encoding = 'UTF-8')
    {
        if (is_array($input)) {
            return array_map(fn($item) => self::sanitize($item, $flags, $encoding), $input);
        }
        
        return htmlspecialchars(strip_tags(trim($input)), $flags, $encoding);
    }

    /**
     * Validate Email
     */
    public static function validateEmail(string $email): bool
    {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }

    /**
     * Validate IP
     */
    public static function validateIP(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }

    /**
     * Validate Username
     */
    public static function validateUsername(string $username): bool
    {
        return preg_match('/^[a-zA-Z0-9_]{3,50}$/', $username) === 1;
    }

    /**
     * Hash Password
     */
    public static function hashPassword(string $password): string
    {
        return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
    }

    /**
     * Verify Password
     */
    public static function verifyPassword(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    /**
     * Generate Random String
     */
    public static function randomString(int $length = 32): string
    {
        return bin2hex(random_bytes($length / 2));
    }

    /**
     * Rate Limiting
     */
    public static function checkRateLimit(string $key, int $maxAttempts = 5, int $window = 300): bool
    {
        if (Config::get('RATE_LIMIT_ENABLED', 'true') !== 'true') {
            return true;
        }
        
        $cacheKey = "rate_limit_{$key}";
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $fullKey = "{$cacheKey}_{$ip}";
        
        if (!isset($_SESSION[$fullKey])) {
            $_SESSION[$fullKey] = [
                'attempts' => 0,
                'reset_time' => time() + $window
            ];
        }
        
        $rateLimit = $_SESSION[$fullKey];
        
        // Reset if window expired
        if (time() > $rateLimit['reset_time']) {
            $_SESSION[$fullKey] = [
                'attempts' => 0,
                'reset_time' => time() + $window
            ];
            return true;
        }
        
        // Check if exceeded
        if ($rateLimit['attempts'] >= $maxAttempts) {
            return false;
        }
        
        // Increment attempts
        $_SESSION[$fullKey]['attempts']++;
        return true;
    }

    /**
     * Get Rate Limit Remaining
     */
    public static function getRateLimitRemaining(string $key): int
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $fullKey = "rate_limit_{$key}_{$ip}";
        
        if (!isset($_SESSION[$fullKey])) {
            return Config::get('RATE_LIMIT_MAX_ATTEMPTS', 5);
        }
        
        $rateLimit = $_SESSION[$fullKey];
        $maxAttempts = Config::get('RATE_LIMIT_MAX_ATTEMPTS', 5);
        
        return max(0, $maxAttempts - $rateLimit['attempts']);
    }

    /**
     * XSS Protection - Escape Output
     */
    public static function escape(string $string): string
    {
        return htmlspecialchars($string, ENT_QUOTES, 'UTF-8');
    }

    /**
     * SQL Injection Protection - Already handled by PDO, but for extra safety
     */
    public static function escapeSQL(string $string): string
    {
        // PDO handles this, but this is for extra safety
        return addslashes($string);
    }
}

