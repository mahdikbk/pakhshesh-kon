<?php

namespace PakhsheshKon\Models;

use PakhsheshKon\Core\Database;

/**
 * مدل ServerGroup
 */
class ServerGroup
{
    private ?int $id = null;
    private string $name;
    private string $createdAt;

    /**
     * ایجاد گروه جدید
     */
    public static function create(string $name): self
    {
        $id = Database::insert('server_groups', [
            'name' => $name
        ]);

        return self::findById($id);
    }

    /**
     * پیدا کردن با ID
     */
    public static function findById(int $id): ?self
    {
        $data = Database::fetchOne("SELECT * FROM server_groups WHERE id = ?", [$id]);
        return $data ? self::fromArray($data) : null;
    }

    /**
     * دریافت تمام گروه‌ها
     */
    public static function all(): array
    {
        $data = Database::fetchAll("SELECT * FROM server_groups ORDER BY created_at DESC");
        return array_map(fn($row) => self::fromArray($row), $data);
    }

    /**
     * حذف گروه
     */
    public function delete(): bool
    {
        return Database::delete('server_groups', ['id' => $this->id]) > 0;
    }

    /**
     * به‌روزرسانی نام
     */
    public function updateName(string $name): bool
    {
        $this->name = $name;
        return Database::update('server_groups', 
            ['name' => $name],
            ['id' => $this->id]
        ) > 0;
    }

    /**
     * ساخت از Array
     */
    private static function fromArray(array $data): self
    {
        $group = new self();
        $group->id = (int)$data['id'];
        $group->name = $data['name'];
        $group->createdAt = $data['created_at'];
        return $group;
    }

    // Getters
    public function getId(): ?int { return $this->id; }
    public function getName(): string { return $this->name; }
    public function getCreatedAt(): string { return $this->createdAt; }
}

