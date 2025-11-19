# راهنمای ارتقای پروژه پخشش کن!

## 🎉 تغییرات اعمال شده

پروژه شما به صورت کامل بازنویسی و بهبود یافته است. تغییرات شامل:

### ✅ بهبودهای امنیتی
- ✅ **CSRF Protection**: تمام فرم‌ها با CSRF Token محافظت می‌شوند
- ✅ **Rate Limiting**: محدودیت تعداد تلاش‌های لاگین
- ✅ **Input Validation**: اعتبارسنجی کامل ورودی‌ها
- ✅ **Password Hashing**: استفاده از bcrypt با cost 12
- ✅ **Session Security**: تنظیمات امنیتی Session
- ✅ **XSS Protection**: Escape کردن تمام خروجی‌ها

### ✅ معماری بهبود یافته
- ✅ **MVC Pattern**: ساختار Model-View-Controller
- ✅ **PSR-4 Autoloading**: استفاده از Composer Autoload
- ✅ **Namespace**: سازماندهی کد با Namespace
- ✅ **Class-based**: تبدیل به OOP
- ✅ **Dependency Injection**: آماده برای DI

### ✅ ویژگی‌های جدید
- ✅ **Logger System**: سیستم لاگ پیشرفته
- ✅ **Session Management**: مدیریت Session بهبود یافته
- ✅ **Database Abstraction**: لایه انتزاعی دیتابیس
- ✅ **Security Helper**: توابع امنیتی
- ✅ **QR Code Service**: سرویس تولید QR کد
- ✅ **V2Ray Service**: مدیریت V2Ray

### ✅ بهبودهای عملکرد
- ✅ **Prepared Statements**: استفاده از PDO Prepared Statements
- ✅ **Connection Pooling**: مدیریت اتصالات
- ✅ **Error Handling**: مدیریت خطاها
- ✅ **Transaction Support**: پشتیبانی از Transaction

## 📁 ساختار جدید

```
pakhshesh-kon/
├── src/                    # کدهای اصلی
│   ├── Core/              # هسته سیستم
│   ├── Models/            # مدل‌های دیتابیس
│   ├── Controllers/       # کنترلرها
│   ├── Services/          # سرویس‌ها
│   └── Helpers/           # توابع کمکی
├── public/                # فایل‌های عمومی
├── views/                 # View ها
├── config/                # تنظیمات
└── tests/                 # تست‌ها
```

## 🚀 نصب و راه‌اندازی

### 1. نصب Dependencies

```bash
composer install
```

### 2. تنظیم فایل .env

کپی کردن `.env.example` به `.env` و تنظیم مقادیر:

```bash
cp .env.example .env
```

### 3. تنظیم دسترسی‌ها

```bash
chmod -R 755 public/
chmod -R 777 public/qrcodes/
chmod -R 755 src/
```

### 4. تنظیم Apache

اطمینان حاصل کنید که DocumentRoot به `public/` اشاره می‌کند.

## 📝 استفاده

### مثال استفاده از Models

```php
use PakhsheshKon\Models\User;

// ایجاد کاربر
$user = User::create(
    'username',
    10, // 10 GB
    3,  // 3 connections
    30, // 30 days
    1   // group_id
);

// پیدا کردن کاربر
$user = User::findById(1);
$user = User::findByUsername('username');
```

### مثال استفاده از Database

```php
use PakhsheshKon\Core\Database;

// Query
$users = Database::fetchAll("SELECT * FROM users");

// Insert
$id = Database::insert('users', [
    'username' => 'test',
    'uuid' => '...'
]);

// Update
Database::update('users', 
    ['username' => 'new_name'],
    ['id' => 1]
);
```

### مثال استفاده از Security

```php
use PakhsheshKon\Core\Security;

// CSRF Token
$token = Security::generateCSRFToken();
Security::validateCSRFToken($token);

// Rate Limiting
if (!Security::checkRateLimit('login', 5, 300)) {
    // Too many attempts
}

// Validation
Security::validateEmail($email);
Security::validateUsername($username);
```

## 🔧 بهبودهای آینده

### در حال توسعه:
- [ ] API RESTful کامل
- [ ] اعلان‌های تلگرام
- [ ] سیستم بکاپ خودکار
- [ ] Cache با Redis
- [ ] Unit Tests
- [ ] Integration Tests
- [ ] Docker Support
- [ ] CI/CD Pipeline

## 📚 مستندات

برای اطلاعات بیشتر به فایل‌های زیر مراجعه کنید:
- `ANALYSIS.md` - تحلیل کامل پروژه
- `PROJECT_STRUCTURE.md` - ساختار پروژه
- `README.md` - راهنمای اصلی

## ⚠️ نکات مهم

1. **فایل .env را در Git commit نکنید**
2. **رمزهای عبور را در .env قرار دهید**
3. **دسترسی‌های فایل‌ها را بررسی کنید**
4. **از HTTPS استفاده کنید**
5. **بکاپ منظم بگیرید**

## 🐛 گزارش باگ

اگر باگی پیدا کردید، لطفاً در GitHub Issues گزارش دهید.

## 📄 لایسنس

این پروژه تحت لایسنس GNU GPL v3 منتشر شده است.

---

**ساخته شده با ❤️ توسط MahdiKBK**

