<?php

namespace PakhsheshKon\Models;

use PakhsheshKon\Core\Database;

/**
 * مدل Ticket
 */
class Ticket
{
    private ?int $id = null;
    private string $title;
    private string $message;
    private int $userId;
    private string $status = 'open';
    private ?string $response = null;
    private string $createdAt;
    private ?string $updatedAt = null;

    /**
     * ایجاد تیکت جدید
     */
    public static function create(string $title, string $message, int $userId): self
    {
        $id = Database::insert('tickets', [
            'title' => $title,
            'message' => $message,
            'user_id' => $userId,
            'status' => 'open'
        ]);

        return self::findById($id);
    }

    /**
     * پیدا کردن با ID
     */
    public static function findById(int $id): ?self
    {
        $data = Database::fetchOne("SELECT * FROM tickets WHERE id = ?", [$id]);
        return $data ? self::fromArray($data) : null;
    }

    /**
     * دریافت تیکت‌های یک کاربر
     */
    public static function findByUser(int $userId): array
    {
        $data = Database::fetchAll(
            "SELECT * FROM tickets WHERE user_id = ? ORDER BY created_at DESC",
            [$userId]
        );

        return array_map(fn($row) => self::fromArray($row), $data);
    }

    /**
     * دریافت تمام تیکت‌ها
     */
    public static function all(string $status = null, int $limit = 100): array
    {
        $sql = "SELECT * FROM tickets";
        $params = [];

        if ($status) {
            $sql .= " WHERE status = ?";
            $params[] = $status;
        }

        $sql .= " ORDER BY created_at DESC LIMIT ?";
        $params[] = $limit;

        $data = Database::fetchAll($sql, $params);
        return array_map(fn($row) => self::fromArray($row), $data);
    }

    /**
     * پاسخ به تیکت
     */
    public function respond(string $response): bool
    {
        $this->response = $response;
        $this->status = 'closed';
        $this->updatedAt = date('Y-m-d H:i:s');

        return Database::update('tickets', [
            'response' => $response,
            'status' => 'closed',
            'updated_at' => $this->updatedAt
        ], ['id' => $this->id]) > 0;
    }

    /**
     * تغییر وضعیت
     */
    public function setStatus(string $status): bool
    {
        $this->status = $status;
        $this->updatedAt = date('Y-m-d H:i:s');

        return Database::update('tickets', [
            'status' => $status,
            'updated_at' => $this->updatedAt
        ], ['id' => $this->id]) > 0;
    }

    /**
     * حذف تیکت
     */
    public function delete(): bool
    {
        return Database::delete('tickets', ['id' => $this->id]) > 0;
    }

    /**
     * ساخت از Array
     */
    private static function fromArray(array $data): self
    {
        $ticket = new self();
        $ticket->id = (int)$data['id'];
        $ticket->title = $data['title'];
        $ticket->message = $data['message'];
        $ticket->userId = (int)$data['user_id'];
        $ticket->status = $data['status'] ?? 'open';
        $ticket->response = $data['response'] ?? null;
        $ticket->createdAt = $data['created_at'];
        $ticket->updatedAt = $data['updated_at'] ?? null;
        return $ticket;
    }

    // Getters
    public function getId(): ?int { return $this->id; }
    public function getTitle(): string { return $this->title; }
    public function getMessage(): string { return $this->message; }
    public function getUserId(): int { return $this->userId; }
    public function getStatus(): string { return $this->status; }
    public function getResponse(): ?string { return $this->response; }
    public function getCreatedAt(): string { return $this->createdAt; }
    public function getUpdatedAt(): ?string { return $this->updatedAt; }
}

