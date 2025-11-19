<?php

namespace PakhsheshKon\Core;

use PDO;
use PDOException;

/**
 * کلاس مدیریت اتصال دیتابیس
 */
class Database
{
    private static ?PDO $instance = null;
    private static array $config = [];

    /**
     * دریافت instance دیتابیس (Singleton Pattern)
     */
    public static function getInstance(): PDO
    {
        if (self::$instance === null) {
            self::connect();
        }
        
        return self::$instance;
    }

    /**
     * اتصال به دیتابیس
     */
    private static function connect(): void
    {
        try {
            $host = Config::get('DB_HOST', 'localhost');
            $dbname = Config::get('DB_NAME', 'pakhshesh_kon');
            $username = Config::get('DB_USER', 'root');
            $password = Config::get('DB_PASS', '');
            
            $dsn = "mysql:host={$host};dbname={$dbname};charset=utf8mb4";
            
            $options = [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci"
            ];
            
            self::$instance = new PDO($dsn, $username, $password, $options);
        } catch (PDOException $e) {
            error_log("Database connection failed: " . $e->getMessage());
            throw new \RuntimeException("خطا در اتصال به دیتابیس. لطفاً با مدیر سیستم تماس بگیرید.");
        }
    }

    /**
     * اجرای Query
     */
    public static function query(string $sql, array $params = []): \PDOStatement
    {
        $db = self::getInstance();
        $stmt = $db->prepare($sql);
        $stmt->execute($params);
        return $stmt;
    }

    /**
     * دریافت یک ردیف
     */
    public static function fetchOne(string $sql, array $params = []): ?array
    {
        $stmt = self::query($sql, $params);
        $result = $stmt->fetch();
        return $result ?: null;
    }

    /**
     * دریافت تمام ردیف‌ها
     */
    public static function fetchAll(string $sql, array $params = []): array
    {
        $stmt = self::query($sql, $params);
        return $stmt->fetchAll();
    }

    /**
     * دریافت یک مقدار
     */
    public static function fetchColumn(string $sql, array $params = [], int $column = 0)
    {
        $stmt = self::query($sql, $params);
        return $stmt->fetchColumn($column);
    }

    /**
     * اجرای Insert و بازگشت ID
     */
    public static function insert(string $table, array $data): int
    {
        $fields = array_keys($data);
        $placeholders = array_map(fn($field) => ":{$field}", $fields);
        
        $sql = "INSERT INTO {$table} (" . implode(', ', $fields) . ") 
                VALUES (" . implode(', ', $placeholders) . ")";
        
        $db = self::getInstance();
        $stmt = $db->prepare($sql);
        $stmt->execute($data);
        
        return (int)$db->lastInsertId();
    }

    /**
     * اجرای Update
     */
    public static function update(string $table, array $data, array $where): int
    {
        $set = [];
        foreach (array_keys($data) as $field) {
            $set[] = "{$field} = :{$field}";
        }
        
        $whereClause = [];
        foreach (array_keys($where) as $field) {
            $whereClause[] = "{$field} = :where_{$field}";
        }
        
        $sql = "UPDATE {$table} SET " . implode(', ', $set) . 
               " WHERE " . implode(' AND ', $whereClause);
        
        $params = array_merge($data, array_combine(
            array_map(fn($k) => "where_{$k}", array_keys($where)),
            array_values($where)
        ));
        
        $stmt = self::query($sql, $params);
        return $stmt->rowCount();
    }

    /**
     * اجرای Delete
     */
    public static function delete(string $table, array $where): int
    {
        $whereClause = [];
        foreach (array_keys($where) as $field) {
            $whereClause[] = "{$field} = :{$field}";
        }
        
        $sql = "DELETE FROM {$table} WHERE " . implode(' AND ', $whereClause);
        $stmt = self::query($sql, $where);
        return $stmt->rowCount();
    }

    /**
     * شروع Transaction
     */
    public static function beginTransaction(): bool
    {
        return self::getInstance()->beginTransaction();
    }

    /**
     * Commit Transaction
     */
    public static function commit(): bool
    {
        return self::getInstance()->commit();
    }

    /**
     * Rollback Transaction
     */
    public static function rollback(): bool
    {
        return self::getInstance()->rollBack();
    }
}

