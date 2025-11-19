<?php

namespace PakhsheshKon\Models;

use PakhsheshKon\Core\Database;
use PakhsheshKon\Core\Security;
use PakhsheshKon\Core\Logger;

/**
 * مدل Admin
 */
class Admin
{
    private ?int $id = null;
    private string $username;
    private string $passwordHash;
    private string $createdAt;

    /**
     * لاگین
     */
    public static function login(string $username, string $password): ?self
    {
        $data = Database::fetchOne("SELECT * FROM admins WHERE username = ?", [$username]);
        
        if (!$data) {
            Logger::log("Login failed: User not found", $username, null, 'WARNING');
            return null;
        }

        if (!Security::verifyPassword($password, $data['password'])) {
            Logger::log("Login failed: Invalid password", $username, null, 'WARNING');
            return null;
        }

        Logger::log("Login successful", $username, null, 'INFO');
        return self::fromArray($data);
    }

    /**
     * پیدا کردن با ID
     */
    public static function findById(int $id): ?self
    {
        $data = Database::fetchOne("SELECT * FROM admins WHERE id = ?", [$id]);
        return $data ? self::fromArray($data) : null;
    }

    /**
     * پیدا کردن با Username
     */
    public static function findByUsername(string $username): ?self
    {
        $data = Database::fetchOne("SELECT * FROM admins WHERE username = ?", [$username]);
        return $data ? self::fromArray($data) : null;
    }

    /**
     * ایجاد ادمین جدید
     */
    public static function create(string $username, string $password): self
    {
        $id = Database::insert('admins', [
            'username' => $username,
            'password' => Security::hashPassword($password)
        ]);

        Logger::log("Admin created", $username, null, 'INFO');
        return self::findById($id);
    }

    /**
     * تغییر رمز عبور
     */
    public function changePassword(string $newPassword): bool
    {
        $this->passwordHash = Security::hashPassword($newPassword);
        return Database::update('admins', 
            ['password' => $this->passwordHash],
            ['id' => $this->id]
        ) > 0;
    }

    /**
     * ساخت از Array
     */
    private static function fromArray(array $data): self
    {
        $admin = new self();
        $admin->id = (int)$data['id'];
        $admin->username = $data['username'];
        $admin->passwordHash = $data['password'];
        $admin->createdAt = $data['created_at'] ?? date('Y-m-d H:i:s');
        return $admin;
    }

    // Getters
    public function getId(): ?int { return $this->id; }
    public function getUsername(): string { return $this->username; }
}

