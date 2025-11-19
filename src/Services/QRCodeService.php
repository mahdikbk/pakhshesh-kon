<?php

namespace PakhsheshKon\Services;

use Endroid\QrCode\QrCode;
use Endroid\QrCode\Writer\PngWriter;

/**
 * سرویس تولید QR کد
 */
class QRCodeService
{
    /**
     * تولید QR کد از لینک
     */
    public static function generate(string $link, string $filename, int $size = 300): string
    {
        $qrCode = QrCode::create($link)
            ->setSize($size)
            ->setMargin(10);

        $writer = new PngWriter();
        $result = $writer->write($qrCode);

        $path = dirname(__DIR__, 2) . '/public/qrcodes/' . $filename;
        $dir = dirname($path);
        
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }

        file_put_contents($path, $result->getString());
        return 'qrcodes/' . $filename;
    }

    /**
     * حذف QR کد
     */
    public static function delete(string $filename): bool
    {
        $path = dirname(__DIR__, 2) . '/public/qrcodes/' . $filename;
        if (file_exists($path)) {
            return unlink($path);
        }
        return false;
    }
}

