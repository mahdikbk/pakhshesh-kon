<?php

namespace PakhsheshKon\Models;

use PakhsheshKon\Core\Database;

/**
 * مدل Server
 */
class Server
{
    private ?int $id = null;
    private int $groupId;
    private string $ip;
    private int $port;
    private ?string $name = null;
    private string $uniqueCode;
    private string $status = 'active';
    private string $createdAt;

    /**
     * ایجاد سرور جدید
     */
    public static function create(
        int $groupId,
        string $ip,
        int $port,
        string $uniqueCode,
        ?string $name = null
    ): self {
        $id = Database::insert('servers', [
            'group_id' => $groupId,
            'ip' => $ip,
            'port' => $port,
            'name' => $name,
            'unique_code' => $uniqueCode,
            'status' => 'active'
        ]);

        return self::findById($id);
    }

    /**
     * پیدا کردن با ID
     */
    public static function findById(int $id): ?self
    {
        $data = Database::fetchOne("SELECT * FROM servers WHERE id = ?", [$id]);
        return $data ? self::fromArray($data) : null;
    }

    /**
     * پیدا کردن با Unique Code
     */
    public static function findByUniqueCode(string $code): ?self
    {
        $data = Database::fetchOne("SELECT * FROM servers WHERE unique_code = ?", [$code]);
        return $data ? self::fromArray($data) : null;
    }

    /**
     * دریافت تمام سرورها
     */
    public static function all(): array
    {
        $data = Database::fetchAll(
            "SELECT s.*, g.name AS group_name 
             FROM servers s 
             JOIN server_groups g ON s.group_id = g.id 
             ORDER BY s.created_at DESC"
        );

        return array_map(fn($row) => self::fromArray($row), $data);
    }

    /**
     * دریافت سرورهای یک گروه
     */
    public static function findByGroup(int $groupId): array
    {
        $data = Database::fetchAll(
            "SELECT s.*, g.name AS group_name 
             FROM servers s 
             JOIN server_groups g ON s.group_id = g.id 
             WHERE s.group_id = ? AND s.status = 'active'
             ORDER BY s.created_at DESC",
            [$groupId]
        );

        return array_map(fn($row) => self::fromArray($row), $data);
    }

    /**
     * تغییر وضعیت
     */
    public function setStatus(string $status): bool
    {
        $this->status = $status;
        return Database::update('servers', 
            ['status' => $status],
            ['id' => $this->id]
        ) > 0;
    }

    /**
     * حذف سرور
     */
    public function delete(): bool
    {
        return Database::delete('servers', ['id' => $this->id]) > 0;
    }

    /**
     * ساخت از Array
     */
    private static function fromArray(array $data): self
    {
        $server = new self();
        $server->id = (int)$data['id'];
        $server->groupId = (int)$data['group_id'];
        $server->ip = $data['ip'];
        $server->port = (int)$data['port'];
        $server->name = $data['name'] ?? null;
        $server->uniqueCode = $data['unique_code'];
        $server->status = $data['status'];
        $server->createdAt = $data['created_at'];
        return $server;
    }

    // Getters
    public function getId(): ?int { return $this->id; }
    public function getGroupId(): int { return $this->groupId; }
    public function getIp(): string { return $this->ip; }
    public function getPort(): int { return $this->port; }
    public function getName(): ?string { return $this->name; }
    public function getUniqueCode(): string { return $this->uniqueCode; }
    public function getStatus(): string { return $this->status; }
    public function getCreatedAt(): string { return $this->createdAt; }
}

