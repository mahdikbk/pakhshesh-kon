<?php

namespace PakhsheshKon\Helpers;

/**
 * کلاس فرمت کردن داده‌ها
 */
class Formatter
{
    /**
     * فرمت کردن بایت به واحد خوانا
     */
    public static function bytes(int $bytes, int $precision = 2): string
    {
        $units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
        
        for ($i = 0; $bytes > 1024 && $i < count($units) - 1; $i++) {
            $bytes /= 1024;
        }
        
        return round($bytes, $precision) . ' ' . $units[$i];
    }

    /**
     * فرمت کردن تاریخ فارسی
     */
    public static function persianDate(string $date, string $format = 'Y/m/d'): string
    {
        $timestamp = strtotime($date);
        $persianMonths = [
            'فروردین', 'اردیبهشت', 'خرداد', 'تیر', 'مرداد', 'شهریور',
            'مهر', 'آبان', 'آذر', 'دی', 'بهمن', 'اسفند'
        ];

        $jDate = self::gregorianToJalali(date('Y', $timestamp), date('m', $timestamp), date('d', $timestamp));
        
        return $jDate[0] . '/' . $jDate[1] . '/' . $jDate[2];
    }

    /**
     * تبدیل میلادی به شمسی
     */
    private static function gregorianToJalali(int $gy, int $gm, int $gd): array
    {
        $g_d_m = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
        $jy = ($gy <= 1600) ? 0 : 979;
        $gy -= ($gy <= 1600) ? 621 : 1600;
        $days = (365 * $gy) + ((int)(($gy + 3) / 4)) - ((int)(($gy + 99) / 100)) + ((int)(($gy + 399) / 400)) - 80 + $gd + $g_d_m[$gm - 1];
        $jy += 33 * ((int)($days / 12053));
        $days %= 12053;
        $jy += 4 * ((int)($days / 1461));
        $days %= 1461;
        $jy += (int)(($days - 1) / 365);
        if ($days > 365) $days = ($days - 1) % 365;
        $jm = ($days < 186) ? 1 + (int)($days / 31) : 7 + (int)(($days - 186) / 30);
        $jd = 1 + (($days < 186) ? ($days % 31) : (($days - 186) % 30));
        return [$jy, $jm, $jd];
    }

    /**
     * فرمت کردن زمان نسبی (مثلاً "2 ساعت پیش")
     */
    public static function timeAgo(string $datetime): string
    {
        $time = time() - strtotime($datetime);
        
        if ($time < 60) {
            return 'چند لحظه پیش';
        } elseif ($time < 3600) {
            $minutes = (int)($time / 60);
            return "{$minutes} دقیقه پیش";
        } elseif ($time < 86400) {
            $hours = (int)($time / 3600);
            return "{$hours} ساعت پیش";
        } elseif ($time < 2592000) {
            $days = (int)($time / 86400);
            return "{$days} روز پیش";
        } elseif ($time < 31536000) {
            $months = (int)($time / 2592000);
            return "{$months} ماه پیش";
        } else {
            $years = (int)($time / 31536000);
            return "{$years} سال پیش";
        }
    }

    /**
     * فرمت کردن عدد با جداکننده هزارگان
     */
    public static function number(int|float $number): string
    {
        return number_format($number, 0, '.', ',');
    }

    /**
     * فرمت کردن درصد
     */
    public static function percentage(float $value, int $decimals = 1): string
    {
        return number_format($value, $decimals, '.', ',') . '%';
    }

    /**
     * فرمت کردن مدت زمان (ثانیه به فرمت خوانا)
     */
    public static function duration(int $seconds): string
    {
        if ($seconds < 60) {
            return "{$seconds} ثانیه";
        } elseif ($seconds < 3600) {
            $minutes = (int)($seconds / 60);
            $secs = $seconds % 60;
            return $secs > 0 ? "{$minutes} دقیقه و {$secs} ثانیه" : "{$minutes} دقیقه";
        } elseif ($seconds < 86400) {
            $hours = (int)($seconds / 3600);
            $minutes = (int)(($seconds % 3600) / 60);
            return $minutes > 0 ? "{$hours} ساعت و {$minutes} دقیقه" : "{$hours} ساعت";
        } else {
            $days = (int)($seconds / 86400);
            $hours = (int)(($seconds % 86400) / 3600);
            return $hours > 0 ? "{$days} روز و {$hours} ساعت" : "{$days} روز";
        }
    }
}

