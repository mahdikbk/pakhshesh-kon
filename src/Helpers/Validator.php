<?php

namespace PakhsheshKon\Helpers;

/**
 * کلاس اعتبارسنجی
 */
class Validator
{
    /**
     * اعتبارسنجی IP
     */
    public static function ip(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }

    /**
     * اعتبارسنجی IPv4
     */
    public static function ipv4(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
    }

    /**
     * اعتبارسنجی IPv6
     */
    public static function ipv6(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
    }

    /**
     * اعتبارسنجی Port
     */
    public static function port(int $port): bool
    {
        return $port >= 1 && $port <= 65535;
    }

    /**
     * اعتبارسنجی UUID
     */
    public static function uuid(string $uuid): bool
    {
        return preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $uuid) === 1;
    }

    /**
     * اعتبارسنجی Domain
     */
    public static function domain(string $domain): bool
    {
        return filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false;
    }

    /**
     * اعتبارسنجی URL
     */
    public static function url(string $url): bool
    {
        return filter_var($url, FILTER_VALIDATE_URL) !== false;
    }

    /**
     * اعتبارسنجی Date
     */
    public static function date(string $date, string $format = 'Y-m-d'): bool
    {
        $d = \DateTime::createFromFormat($format, $date);
        return $d && $d->format($format) === $date;
    }

    /**
     * اعتبارسنجی Phone
     */
    public static function phone(string $phone): bool
    {
        // فرمت: +989123456789 یا 09123456789
        return preg_match('/^(\+98|0)?9\d{9}$/', $phone) === 1;
    }

    /**
     * اعتبارسنجی Password Strength
     */
    public static function passwordStrength(string $password): array
    {
        $strength = 0;
        $feedback = [];

        if (strlen($password) >= 8) {
            $strength++;
        } else {
            $feedback[] = 'رمز عبور باید حداقل 8 کاراکتر باشد';
        }

        if (preg_match('/[a-z]/', $password)) {
            $strength++;
        } else {
            $feedback[] = 'رمز عبور باید شامل حروف کوچک باشد';
        }

        if (preg_match('/[A-Z]/', $password)) {
            $strength++;
        } else {
            $feedback[] = 'رمز عبور باید شامل حروف بزرگ باشد';
        }

        if (preg_match('/[0-9]/', $password)) {
            $strength++;
        } else {
            $feedback[] = 'رمز عبور باید شامل اعداد باشد';
        }

        if (preg_match('/[^a-zA-Z0-9]/', $password)) {
            $strength++;
        } else {
            $feedback[] = 'رمز عبور باید شامل کاراکترهای خاص باشد';
        }

        $levels = ['خیلی ضعیف', 'ضعیف', 'متوسط', 'قوی', 'خیلی قوی'];
        $level = $levels[min($strength, 4)];

        return [
            'strength' => $strength,
            'level' => $level,
            'feedback' => $feedback,
            'is_strong' => $strength >= 4
        ];
    }
}

