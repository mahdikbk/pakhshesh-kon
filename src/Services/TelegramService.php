<?php

namespace PakhsheshKon\Services;

use PakhsheshKon\Core\Config;
use PakhsheshKon\Core\Logger;

/**
 * سرویس اعلان تلگرام
 */
class TelegramService
{
    private static ?string $botToken = null;
    private static ?string $chatId = null;
    private static bool $enabled = false;

    /**
     * مقداردهی اولیه
     */
    private static function init(): void
    {
        if (self::$botToken !== null) {
            return;
        }

        self::$enabled = Config::get('TELEGRAM_ENABLED', 'false') === 'true';
        self::$botToken = Config::get('TELEGRAM_BOT_TOKEN', '');
        self::$chatId = Config::get('TELEGRAM_CHAT_ID', '');
    }

    /**
     * ارسال پیام
     */
    public static function sendMessage(string $message, string $parseMode = 'HTML'): bool
    {
        self::init();

        if (!self::$enabled || empty(self::$botToken) || empty(self::$chatId)) {
            return false;
        }

        $url = "https://api.telegram.org/bot" . self::$botToken . "/sendMessage";
        
        $data = [
            'chat_id' => self::$chatId,
            'text' => $message,
            'parse_mode' => $parseMode
        ];

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode !== 200) {
            Logger::error("Telegram send failed", ['response' => $response, 'http_code' => $httpCode]);
            return false;
        }

        return true;
    }

    /**
     * اعلان اتمام ترافیک کاربر
     */
    public static function notifyTrafficExceeded(string $username, int $trafficUsed, int $trafficLimit): bool
    {
        $message = "⚠️ <b>هشدار: اتمام ترافیک</b>\n\n";
        $message .= "کاربر: <code>{$username}</code>\n";
        $message .= "ترافیک مصرف شده: " . self::formatBytes($trafficUsed) . "\n";
        $message .= "محدودیت: " . self::formatBytes($trafficLimit);

        return self::sendMessage($message);
    }

    /**
     * اعلان انقضای کاربر
     */
    public static function notifyUserExpired(string $username, string $expiryDate): bool
    {
        $message = "⏰ <b>هشدار: انقضای کاربر</b>\n\n";
        $message .= "کاربر: <code>{$username}</code>\n";
        $message .= "تاریخ انقضا: {$expiryDate}";

        return self::sendMessage($message);
    }

    /**
     * اعلان سرور آفلاین
     */
    public static function notifyServerOffline(string $serverName, string $ip): bool
    {
        $message = "🔴 <b>هشدار: سرور آفلاین</b>\n\n";
        $message .= "سرور: <code>{$serverName}</code>\n";
        $message .= "IP: <code>{$ip}</code>";

        return self::sendMessage($message);
    }

    /**
     * اعلان سرور آنلاین شد
     */
    public static function notifyServerOnline(string $serverName, string $ip): bool
    {
        $message = "🟢 <b>اطلاعیه: سرور آنلاین</b>\n\n";
        $message .= "سرور: <code>{$serverName}</code>\n";
        $message .= "IP: <code>{$ip}</code>";

        return self::sendMessage($message);
    }

    /**
     * فرمت کردن بایت
     */
    private static function formatBytes(int $bytes, int $precision = 2): string
    {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        
        for ($i = 0; $bytes > 1024 && $i < count($units) - 1; $i++) {
            $bytes /= 1024;
        }
        
        return round($bytes, $precision) . ' ' . $units[$i];
    }
}

