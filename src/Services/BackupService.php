<?php

namespace PakhsheshKon\Services;

use PakhsheshKon\Core\Config;
use PakhsheshKon\Core\Database;
use PakhsheshKon\Core\Logger;

/**
 * سرویس بکاپ خودکار
 */
class BackupService
{
    /**
     * ایجاد بکاپ دیتابیس
     */
    public static function backupDatabase(): ?string
    {
        $backupPath = Config::get('BACKUP_PATH', '/var/backups/pakhsheshkon');
        $dbName = Config::get('DB_NAME', 'pakhshesh_kon');
        $dbUser = Config::get('DB_USER', 'root');
        $dbPass = Config::get('DB_PASS', '');

        if (!is_dir($backupPath)) {
            mkdir($backupPath, 0755, true);
        }

        $filename = "backup_{$dbName}_" . date('Y-m-d_H-i-s') . ".sql";
        $filepath = $backupPath . '/' . $filename;

        $command = sprintf(
            "mysqldump -u%s -p%s %s > %s 2>&1",
            escapeshellarg($dbUser),
            escapeshellarg($dbPass),
            escapeshellarg($dbName),
            escapeshellarg($filepath)
        );

        exec($command, $output, $returnCode);

        if ($returnCode !== 0) {
            Logger::error("Database backup failed", ['output' => $output, 'return_code' => $returnCode]);
            return null;
        }

        if (!file_exists($filepath) || filesize($filepath) === 0) {
            Logger::error("Database backup file is empty or not created");
            return null;
        }

        // فشرده‌سازی
        $compressed = $filepath . '.gz';
        if (function_exists('gzencode')) {
            $data = file_get_contents($filepath);
            file_put_contents($compressed, gzencode($data, 9));
            unlink($filepath);
            $filepath = $compressed;
        }

        Logger::info("Database backup created", ['file' => $filepath]);
        return $filepath;
    }

    /**
     * بکاپ فایل‌ها
     */
    public static function backupFiles(array $paths): ?string
    {
        $backupPath = Config::get('BACKUP_PATH', '/var/backups/pakhsheshkon');
        
        if (!is_dir($backupPath)) {
            mkdir($backupPath, 0755, true);
        }

        $filename = "files_backup_" . date('Y-m-d_H-i-s') . ".tar.gz";
        $filepath = $backupPath . '/' . $filename;

        $tarPaths = implode(' ', array_map('escapeshellarg', $paths));
        $command = "tar -czf " . escapeshellarg($filepath) . " {$tarPaths} 2>&1";

        exec($command, $output, $returnCode);

        if ($returnCode !== 0) {
            Logger::error("Files backup failed", ['output' => $output, 'return_code' => $returnCode]);
            return null;
        }

        Logger::info("Files backup created", ['file' => $filepath]);
        return $filepath;
    }

    /**
     * پاک کردن بکاپ‌های قدیمی
     */
    public static function cleanOldBackups(int $retentionDays = 30): int
    {
        $backupPath = Config::get('BACKUP_PATH', '/var/backups/pakhsheshkon');
        $retentionDays = (int)Config::get('BACKUP_RETENTION_DAYS', $retentionDays);

        if (!is_dir($backupPath)) {
            return 0;
        }

        $files = glob($backupPath . '/backup_*');
        $deleted = 0;
        $cutoffTime = time() - ($retentionDays * 24 * 60 * 60);

        foreach ($files as $file) {
            if (filemtime($file) < $cutoffTime) {
                if (unlink($file)) {
                    $deleted++;
                }
            }
        }

        if ($deleted > 0) {
            Logger::info("Cleaned old backups", ['deleted' => $deleted]);
        }

        return $deleted;
    }

    /**
     * لیست بکاپ‌ها
     */
    public static function listBackups(): array
    {
        $backupPath = Config::get('BACKUP_PATH', '/var/backups/pakhsheshkon');

        if (!is_dir($backupPath)) {
            return [];
        }

        $files = glob($backupPath . '/backup_*');
        $backups = [];

        foreach ($files as $file) {
            $backups[] = [
                'filename' => basename($file),
                'path' => $file,
                'size' => filesize($file),
                'created' => date('Y-m-d H:i:s', filemtime($file))
            ];
        }

        // Sort by creation date (newest first)
        usort($backups, fn($a, $b) => strtotime($b['created']) - strtotime($a['created']));

        return $backups;
    }

    /**
     * بازیابی دیتابیس از بکاپ
     */
    public static function restoreDatabase(string $backupFile): bool
    {
        $dbName = Config::get('DB_NAME', 'pakhshesh_kon');
        $dbUser = Config::get('DB_USER', 'root');
        $dbPass = Config::get('DB_PASS', '');

        if (!file_exists($backupFile)) {
            Logger::error("Backup file not found", ['file' => $backupFile]);
            return false;
        }

        // Decompress if needed
        if (substr($backupFile, -3) === '.gz') {
            $decompressed = str_replace('.gz', '', $backupFile);
            $data = gzdecode(file_get_contents($backupFile));
            file_put_contents($decompressed, $data);
            $backupFile = $decompressed;
        }

        $command = sprintf(
            "mysql -u%s -p%s %s < %s 2>&1",
            escapeshellarg($dbUser),
            escapeshellarg($dbPass),
            escapeshellarg($dbName),
            escapeshellarg($backupFile)
        );

        exec($command, $output, $returnCode);

        if ($returnCode !== 0) {
            Logger::error("Database restore failed", ['output' => $output, 'return_code' => $returnCode]);
            return false;
        }

        Logger::info("Database restored", ['file' => $backupFile]);
        return true;
    }
}

