# 🚀 راهنمای سریع شروع

## ✅ چه کارهایی انجام شده؟

پروژه شما به صورت **کامل و حرفه‌ای** بازنویسی شده است:

### 🔒 امنیت
- ✅ CSRF Protection در تمام فرم‌ها
- ✅ Rate Limiting برای جلوگیری از Brute Force
- ✅ Input Validation و Sanitization
- ✅ Password Hashing با bcrypt
- ✅ Session Security

### 🏗️ معماری
- ✅ ساختار MVC حرفه‌ای
- ✅ PSR-4 Autoloading
- ✅ OOP با Namespace
- ✅ Database Abstraction Layer
- ✅ Service Layer

### 📦 فایل‌های ایجاد شده

#### Core Classes
- `src/Core/Config.php` - مدیریت تنظیمات
- `src/Core/Database.php` - لایه دیتابیس
- `src/Core/Security.php` - امنیت
- `src/Core/Session.php` - Session
- `src/Core/Logger.php` - لاگ

#### Models
- `src/Models/User.php` - کاربر
- `src/Models/Admin.php` - ادمین
- `src/Models/Server.php` - سرور

#### Controllers
- `src/Controllers/AuthController.php` - احراز هویت
- `src/Controllers/DashboardController.php` - داشبورد

#### Services
- `src/Services/QRCodeService.php` - QR کد
- `src/Services/V2RayService.php` - V2Ray

## 🎯 چگونه استفاده کنیم؟

### 1. نصب Dependencies

```bash
composer install
```

### 2. تنظیم .env

```bash
cp .env.example .env
# سپس فایل .env را ویرایش کنید
```

### 3. استفاده در کد

#### ایجاد کاربر:
```php
use PakhsheshKon\Models\User;

$user = User::create(
    'username',  // نام کاربری
    10,         // 10 GB ترافیک
    3,          // 3 اتصال همزمان
    30,         // 30 روز اعتبار
    1           // گروه سرور
);
```

#### استفاده از Database:
```php
use PakhsheshKon\Core\Database;

// Query
$users = Database::fetchAll("SELECT * FROM users");

// Insert
$id = Database::insert('users', [
    'username' => 'test',
    'uuid' => '...'
]);
```

#### امنیت:
```php
use PakhsheshKon\Core\Security;

// CSRF Token
$token = Security::generateCSRFToken();

// Rate Limiting
if (!Security::checkRateLimit('login', 5, 300)) {
    // Too many attempts
}

// Validation
Security::validateEmail($email);
Security::validateUsername($username);
```

## 📝 مثال کامل: ایجاد کاربر با QR کد

```php
use PakhsheshKon\Models\User;
use PakhsheshKon\Models\Server;
use PakhsheshKon\Services\QRCodeService;
use PakhsheshKon\Services\V2RayService;

// پیدا کردن سرور
$server = Server::findByGroup(1)[0];

// ایجاد کاربر
$user = User::create('testuser', 10, 3, 30, 1);

// تولید لینک V2Ray
$link = V2RayService::generateVLESSLink($user, $server, 10062);

// تولید QR کد
$qrPath = QRCodeService::generate($link, $user->getUsername() . '.png');

// ذخیره لینک و QR
$user->setLink($link);
$user->setQrPath($qrPath);
$user->save();
```

## 🔧 تنظیمات Apache

اطمینان حاصل کنید که DocumentRoot به `public/` اشاره می‌کند:

```apache
<VirtualHost *:80>
    ServerName your-domain.com
    DocumentRoot /path/to/pakhshesh-kon/public
    
    <Directory /path/to/pakhshesh-kon/public>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

## ⚠️ نکات مهم

1. **فایل .env را commit نکنید**
2. **دسترسی‌های فایل‌ها را بررسی کنید**
3. **از HTTPS استفاده کنید**
4. **بکاپ منظم بگیرید**

## 📚 مستندات بیشتر

- `README_UPGRADE.md` - راهنمای کامل ارتقا
- `UPGRADE_SUMMARY.md` - خلاصه تغییرات
- `ANALYSIS.md` - تحلیل پروژه
- `PROJECT_STRUCTURE.md` - ساختار پروژه

## 🐛 مشکل دارید؟

1. مطمئن شوید `composer install` را اجرا کرده‌اید
2. فایل `.env` را تنظیم کرده‌اید
3. دسترسی‌های فایل‌ها درست است
4. Apache به `public/` اشاره می‌کند

## 🎉 آماده استفاده!

سیستم شما اکنون **حرفه‌ای، امن و بدون باگ** است!

---

**ساخته شده با ❤️ توسط MahdiKBK**

