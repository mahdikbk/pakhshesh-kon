<?php

namespace PakhsheshKon\Models;

use PakhsheshKon\Core\Database;

/**
 * مدل Monitoring
 */
class Monitoring
{
    private ?int $id = null;
    private int $serverId;
    private ?int $activeUsers = null;
    private ?string $bandwidth = null;
    private ?int $ping = null;
    private string $recordedAt;

    /**
     * ثبت داده مانیتورینگ
     */
    public static function create(
        int $serverId,
        ?int $activeUsers = null,
        ?string $bandwidth = null,
        ?int $ping = null
    ): self {
        $id = Database::insert('monitoring', [
            'server_id' => $serverId,
            'active_users' => $activeUsers,
            'bandwidth' => $bandwidth,
            'ping' => $ping
        ]);

        return self::findById($id);
    }

    /**
     * پیدا کردن با ID
     */
    public static function findById(int $id): ?self
    {
        $data = Database::fetchOne("SELECT * FROM monitoring WHERE id = ?", [$id]);
        return $data ? self::fromArray($data) : null;
    }

    /**
     * دریافت آخرین داده‌های یک سرور
     */
    public static function getLatestByServer(int $serverId): ?self
    {
        $data = Database::fetchOne(
            "SELECT * FROM monitoring WHERE server_id = ? ORDER BY recorded_at DESC LIMIT 1",
            [$serverId]
        );
        return $data ? self::fromArray($data) : null;
    }

    /**
     * دریافت داده‌های یک سرور در بازه زمانی
     */
    public static function getByServer(int $serverId, int $days = 5): array
    {
        $data = Database::fetchAll(
            "SELECT * FROM monitoring 
             WHERE server_id = ? AND recorded_at >= DATE_SUB(NOW(), INTERVAL ? DAY) 
             ORDER BY recorded_at",
            [$serverId, $days]
        );

        return array_map(fn($row) => self::fromArray($row), $data);
    }

    /**
     * دریافت تمام داده‌های مانیتورینگ
     */
    public static function all(int $limit = 100): array
    {
        $data = Database::fetchAll(
            "SELECT * FROM monitoring ORDER BY recorded_at DESC LIMIT ?",
            [$limit]
        );

        return array_map(fn($row) => self::fromArray($row), $data);
    }

    /**
     * پاک کردن داده‌های قدیمی
     */
    public static function cleanOld(int $days = 30): int
    {
        return Database::query(
            "DELETE FROM monitoring WHERE recorded_at < DATE_SUB(NOW(), INTERVAL ? DAY)",
            [$days]
        )->rowCount();
    }

    /**
     * ساخت از Array
     */
    private static function fromArray(array $data): self
    {
        $monitoring = new self();
        $monitoring->id = (int)$data['id'];
        $monitoring->serverId = (int)$data['server_id'];
        $monitoring->activeUsers = $data['active_users'] ? (int)$data['active_users'] : null;
        $monitoring->bandwidth = $data['bandwidth'] ?? null;
        $monitoring->ping = $data['ping'] ? (int)$data['ping'] : null;
        $monitoring->recordedAt = $data['recorded_at'];
        return $monitoring;
    }

    // Getters
    public function getId(): ?int { return $this->id; }
    public function getServerId(): int { return $this->serverId; }
    public function getActiveUsers(): ?int { return $this->activeUsers; }
    public function getBandwidth(): ?string { return $this->bandwidth; }
    public function getPing(): ?int { return $this->ping; }
    public function getRecordedAt(): string { return $this->recordedAt; }
}

