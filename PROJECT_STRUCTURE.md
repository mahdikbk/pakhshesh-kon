# ساختار پروژه حرفه‌ای پخشش کن!

```
pakhshesh-kon/
├── src/                          # کدهای اصلی
│   ├── Core/                     # هسته سیستم
│   │   ├── Database.php          # کلاس اتصال دیتابیس
│   │   ├── Security.php          # امنیت (CSRF, Rate Limit, Validation)
│   │   ├── Session.php           # مدیریت Session
│   │   ├── Logger.php            # سیستم لاگ
│   │   └── Config.php            # تنظیمات
│   ├── Models/                   # مدل‌های دیتابیس
│   │   ├── User.php
│   │   ├── Server.php
│   │   ├── ServerGroup.php
│   │   ├── Monitoring.php
│   │   ├── Ticket.php
│   │   └── Admin.php
│   ├── Controllers/              # کنترلرها
│   │   ├── AuthController.php
│   │   ├── UserController.php
│   │   ├── ServerController.php
│   │   ├── DashboardController.php
│   │   ├── MonitoringController.php
│   │   └── ApiController.php
│   ├── Services/                 # سرویس‌ها
│   │   ├── V2RayService.php      # مدیریت V2Ray
│   │   ├── QRCodeService.php     # تولید QR کد
│   │   ├── TelegramService.php   # اعلان تلگرام
│   │   ├── BackupService.php     # بکاپ خودکار
│   │   └── LoadBalancerService.php
│   ├── Middleware/               # میدل‌ورها
│   │   ├── AuthMiddleware.php
│   │   ├── RateLimitMiddleware.php
│   │   └── CSRFMiddleware.php
│   └── Helpers/                  # توابع کمکی
│       ├── Validator.php
│       ├── Formatter.php
│       └── Utils.php
├── public/                       # فایل‌های عمومی
│   ├── index.php                 # Entry point
│   ├── assets/
│   │   ├── css/
│   │   ├── js/
│   │   └── fonts/
│   └── qrcodes/
├── views/                        # View ها
│   ├── layouts/
│   │   ├── main.php
│   │   └── auth.php
│   ├── auth/
│   │   └── login.php
│   ├── dashboard/
│   │   └── index.php
│   ├── users/
│   │   ├── index.php
│   │   └── create.php
│   └── ...
├── config/                       # فایل‌های تنظیمات
│   ├── database.php
│   ├── app.php
│   └── telegram.php
├── tests/                        # تست‌ها
│   ├── Unit/
│   ├── Integration/
│   └── E2E/
├── vendor/                       # Composer dependencies
├── install.sh                    # اسکریپت نصب بهبود یافته
├── composer.json
├── .env.example
└── README.md
```

