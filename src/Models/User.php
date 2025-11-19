<?php

namespace PakhsheshKon\Models;

use PakhsheshKon\Core\Database;
use PakhsheshKon\Core\Security;

/**
 * مدل User
 */
class User
{
    private ?int $id = null;
    private string $username;
    private string $uuid;
    private int $serverGroupId;
    private int $trafficLimit;
    private int $trafficUsed = 0;
    private int $connectionLimit;
    private string $expiryDate;
    private ?string $qrPath = null;
    private ?string $link = null;
    private string $createdAt;

    /**
     * ایجاد کاربر جدید
     */
    public static function create(
        string $username,
        int $trafficLimit,
        int $connectionLimit,
        int $days,
        int $serverGroupId,
        string $uuid = null,
        string $link = null,
        string $qrPath = null
    ): self {
        $uuid = $uuid ?? self::generateUUID();
        $expiryDate = date('Y-m-d', strtotime("+{$days} days"));
        
        $id = Database::insert('users', [
            'username' => $username,
            'uuid' => $uuid,
            'server_group_id' => $serverGroupId,
            'traffic_limit' => $trafficLimit * 1024 * 1024 * 1024, // Convert to bytes
            'traffic_used' => 0,
            'connection_limit' => $connectionLimit,
            'expiry_date' => $expiryDate,
            'qr_path' => $qrPath,
            'link' => $link
        ]);

        return self::findById($id);
    }

    /**
     * پیدا کردن کاربر با ID
     */
    public static function findById(int $id): ?self
    {
        $data = Database::fetchOne("SELECT * FROM users WHERE id = ?", [$id]);
        return $data ? self::fromArray($data) : null;
    }

    /**
     * پیدا کردن کاربر با Username
     */
    public static function findByUsername(string $username): ?self
    {
        $data = Database::fetchOne("SELECT * FROM users WHERE username = ?", [$username]);
        return $data ? self::fromArray($data) : null;
    }

    /**
     * پیدا کردن کاربر با UUID
     */
    public static function findByUUID(string $uuid): ?self
    {
        $data = Database::fetchOne("SELECT * FROM users WHERE uuid = ?", [$uuid]);
        return $data ? self::fromArray($data) : null;
    }

    /**
     * دریافت تمام کاربران
     */
    public static function all(int $limit = 100, int $offset = 0): array
    {
        $data = Database::fetchAll(
            "SELECT u.*, g.name AS group_name 
             FROM users u 
             JOIN server_groups g ON u.server_group_id = g.id 
             ORDER BY u.created_at DESC 
             LIMIT ? OFFSET ?",
            [$limit, $offset]
        );

        return array_map(fn($row) => self::fromArray($row), $data);
    }

    /**
     * دریافت کاربران یک گروه
     */
    public static function findByGroup(int $groupId): array
    {
        $data = Database::fetchAll(
            "SELECT u.*, g.name AS group_name 
             FROM users u 
             JOIN server_groups g ON u.server_group_id = g.id 
             WHERE u.server_group_id = ? 
             ORDER BY u.created_at DESC",
            [$groupId]
        );

        return array_map(fn($row) => self::fromArray($row), $data);
    }

    /**
     * به‌روزرسانی ترافیک مصرف شده
     */
    public function updateTraffic(int $bytes): bool
    {
        $this->trafficUsed += $bytes;
        
        return Database::update('users', 
            ['traffic_used' => $this->trafficUsed],
            ['id' => $this->id]
        ) > 0;
    }

    /**
     * بررسی انقضا
     */
    public function isExpired(): bool
    {
        return strtotime($this->expiryDate) < time();
    }

    /**
     * بررسی محدودیت ترافیک
     */
    public function hasTrafficLeft(): bool
    {
        return $this->trafficUsed < $this->trafficLimit;
    }

    /**
     * حذف کاربر
     */
    public function delete(): bool
    {
        return Database::delete('users', ['id' => $this->id]) > 0;
    }

    /**
     * ذخیره تغییرات
     */
    public function save(): bool
    {
        return Database::update('users', [
            'username' => $this->username,
            'uuid' => $this->uuid,
            'server_group_id' => $this->serverGroupId,
            'traffic_limit' => $this->trafficLimit,
            'traffic_used' => $this->trafficUsed,
            'connection_limit' => $this->connectionLimit,
            'expiry_date' => $this->expiryDate,
            'qr_path' => $this->qrPath,
            'link' => $this->link
        ], ['id' => $this->id]) > 0;
    }

    /**
     * ساخت از Array
     */
    private static function fromArray(array $data): self
    {
        $user = new self();
        $user->id = (int)$data['id'];
        $user->username = $data['username'];
        $user->uuid = $data['uuid'];
        $user->serverGroupId = (int)$data['server_group_id'];
        $user->trafficLimit = (int)$data['traffic_limit'];
        $user->trafficUsed = (int)$data['traffic_used'];
        $user->connectionLimit = (int)$data['connection_limit'];
        $user->expiryDate = $data['expiry_date'];
        $user->qrPath = $data['qr_path'] ?? null;
        $user->link = $data['link'] ?? null;
        $user->createdAt = $data['created_at'];
        return $user;
    }

    /**
     * تولید UUID
     */
    private static function generateUUID(): string
    {
        return sprintf(
            '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            mt_rand(0, 0x0fff) | 0x4000,
            mt_rand(0, 0x3fff) | 0x8000,
            mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            mt_rand(0, 0xffff)
        );
    }

    // Getters
    public function getId(): ?int { return $this->id; }
    public function getUsername(): string { return $this->username; }
    public function getUUID(): string { return $this->uuid; }
    public function getServerGroupId(): int { return $this->serverGroupId; }
    public function getTrafficLimit(): int { return $this->trafficLimit; }
    public function getTrafficUsed(): int { return $this->trafficUsed; }
    public function getConnectionLimit(): int { return $this->connectionLimit; }
    public function getExpiryDate(): string { return $this->expiryDate; }
    public function getQrPath(): ?string { return $this->qrPath; }
    public function getLink(): ?string { return $this->link; }
    public function getCreatedAt(): string { return $this->createdAt; }

    // Setters
    public function setUsername(string $username): void { $this->username = $username; }
    public function setTrafficLimit(int $limit): void { $this->trafficLimit = $limit; }
    public function setConnectionLimit(int $limit): void { $this->connectionLimit = $limit; }
    public function setExpiryDate(string $date): void { $this->expiryDate = $date; }
    public function setQrPath(?string $path): void { $this->qrPath = $path; }
    public function setLink(?string $link): void { $this->link = $link; }
}

