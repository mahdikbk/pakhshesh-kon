<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>پخشش کن! (Pakhshesh Kon)</title>
    <style>
        @font-face {
            font-family: 'Yekan';
            src: url('https://raw.githubusercontent.com/DediData/Yekan-Font/master/font/Yekan.ttf') format('truetype');
        }
        body {
            font-family: 'Yekan', Arial, sans-serif;
            background: #f4f7fa;
            color: #333;
            line-height: 1.6;
            margin: 0;
            padding: 0;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            background: linear-gradient(135deg, #1e3c72, #2a5298);
            color: white;
            text-align: center;
            padding: 40px 20px;
            border-radius: 0 0 20px 20px;
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
        }
        header img {
            max-width: 200px;
            margin-bottom: 20px;
        }
        header h1 {
            font-size: 2.5em;
            margin: 0;
        }
        section {
            margin: 40px 0;
        }
        h2 {
            color: #1e3c72;
            font-size: 1.8em;
            border-bottom: 2px solid #2a5298;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        th, td {
            padding: 15px;
            text-align: right;
            border-bottom: 1px solid #ddd;
        }
        th {
            background: #2a5298;
            color: white;
        }
        tr:hover {
            background: #f1f5f9;
        }
        code {
            background: #f4f4f4;
            padding: 2px 5px;
            border-radius: 4px;
            font-family: monospace;
        }
        pre {
            background: #1e3c72;
            color: white;
            padding: 20px;
            border-radius: 10px;
            overflow-x: auto;
            direction: ltr;
            text-align: left;
        }
        a {
            color: #2a5298;
            text-decoration: none;
            transition: color 0.3s;
        }
        a:hover {
            color: #1e3c72;
            text-decoration: underline;
        }
        .badges {
            margin: 20px 0;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        .badges img {
            height: 25px;
        }
        ul, ol {
            margin: 20px 0;
            padding-right: 30px;
        }
        li {
            margin-bottom: 10px;
        }
        footer {
            background: #1e3c72;
            color: white;
            text-align: center;
            padding: 20px;
            margin-top: 40px;
        }
        @media (max-width: 768px) {
            header h1 {
                font-size: 1.8em;
            }
            table, th, td {
                font-size: 0.9em;
            }
            .container {
                padding: 10px;
            }
        }
    </style>
</head>
<body>
    <header>
        <img src="assets/images/logo.png" alt="Pakhshesh Kon Logo">
        <h1>پخشش کن! (Pakhshesh Kon)</h1>
        <p>پنل مدیریت VPN پیشرفته با V2Ray و رابط کاربری شیک</p>
        <div class="badges">
            <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
            <a href="https://github.com/mahdikbk/pakhshesh-kon/releases"><img src="https://img.shields.io/badge/Version-1.0.0-blue.svg" alt="Version"></a>
            <a href="https://github.com/mahdikbk/pakhshesh-kon/issues"><img src="https://img.shields.io/github/issues/mahdikbk/pakhshesh-kon" alt="GitHub Issues"></a>
        </div>
    </header>

    <div class="container">
        <section id="introduction">
            <h2>معرفی</h2>
            <p><strong>پخشش کن!</strong> یه پنل مدیریت VPN حرفه‌ایه که با <strong>V2Ray</strong> طراحی شده تا اتصال امن و سریع به سرورهای ایران و خارجی رو فراهم کنه. این پروژه با رابط کاربری شیک، فونت زیبای <strong>یکان</strong>، و دیزاین مدرن با استایل‌های CSS خالص، تجربه‌ای بی‌نظیر برای مدیریت سرورها و کاربران ارائه می‌ده. از مانیتورینگ real-time گرفته تا اعلان‌های تلگرام و نمودارهای واقعی، همه‌چیز برای یه سیستم خفن آماده‌ست!</p>
        </section>

        <section id="features">
            <h2>ویژگی‌ها</h2>
            <table>
                <thead>
                    <tr>
                        <th>ویژگی</th>
                        <th>توضیحات</th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td>اتصال V2Ray</td>
                        <td>پشتیبانی از پروتکل‌های VLESS+TLS و VMess+WS برای اتصال به سرورهای ایران و خارجی.</td>
                    </tr>
                    <tr>
                        <td>مانیتورینگ Real-time</td>
                        <td>نمایش زنده پینگ، ترافیک، و کاربران فعال با داده‌های واقعی از سرورها.</td>
                    </tr>
                    <tr>
                        <td>نمودارهای واقعی</td>
                        <td>نمودارهای ترافیک، پینگ، و کاربران فعال با داده‌های واقعی از دیتابیس.</td>
                    </tr>
                    <tr>
                        <td>دیزاین جذاب</td>
                        <td>رابط کاربری شیک با CSS خالص، انیمیشن‌های نرم، و فونت یکان.</td>
                    </tr>
                    <tr>
                        <td>آپدیت خودکار</td>
                        <td>به‌روزرسانی پنل با AJAX و لودینگ انیمیشنی زیبا.</td>
                    </tr>
                    <tr>
                        <td>اعلان تلگرام</td>
                        <td>ارسال هشدارهای مهم (مثل اتمام ترافیک یا سرور آفلاین) به تلگرام ادمین.</td>
                    </tr>
                    <tr>
                        <td>فیلتر پیشرفته</td>
                        <td>جستجو و فیلتر کاربران و سرورها بر اساس نام، گروه، یا وضعیت.</td>
                    </tr>
                    <tr>
                        <td>دانلود لینک‌های گروهی</td>
                        <td>امکان دانلود لینک‌های V2Ray همه کاربران به‌صورت ZIP.</td>
                    </tr>
                    <tr>
                        <td>مدیریت چندکاربره</td>
                        <td>نقش‌های ادمین، مدیر، و ناظر با دسترسی‌های متفاوت.</td>
                    </tr>
                    <tr>
                        <td>تقویم انقضا</td>
                        <td>نمایش تاریخ انقضای کاربران در قالب تقویم.</td>
                    </tr>
                    <tr>
                        <td>نوتیفیکیشن مرورگر</td>
                        <td>اعلان‌های مرورگر برای رویدادهای مهم.</td>
                    </tr>
                    <tr>
                        <td>پشتیبانی IPv6</td>
                        <td>تنظیمات V2Ray با پشتیبانی کامل از IPv6.</td>
                    </tr>
                    <tr>
                        <td>مانیتورینگ DNS</td>
                        <td>نمایش وضعیت DNS دامنه و هشدار مشکلات.</td>
                    </tr>
                    <tr>
                        <td>تست سرعت سرور</td>
                        <td>ابزار داخلی برای تست سرعت و پینگ سرورهای خارجی.</td>
                    </tr>
                    <tr>
                        <td>مدیریت بکاپ</td>
                        <td>دانلود و بازیابی بکاپ‌های دیتابیس از پنل.</td>
                    </tr>
                </tbody>
            </table>
        </section>

        <section id="prerequisites">
            <h2>پیش‌نیازها</h2>
            <p>قبل از نصب، مطمئن بشید سرورتون این شرایط رو داره:</p>
            <ul>
                <li><strong>سیستم‌عامل</strong>: Ubuntu 20.04 یا بالاتر</li>
                <li><strong>حداقل سخت‌افزار</strong>:
                    <ul>
                        <li>CPU: 1 هسته</li>
                        <li>RAM: 512MB</li>
                        <li>فضای دیسک: 5GB</li>
                    </ul>
                </li>
                <li><strong>دسترسی‌ها</strong>: دسترسی root برای نصب پکیج‌ها</li>
                <li><strong>اتصال اینترنت</strong>: برای دانلود وابستگی‌ها و گواهی SSL</li>
                <li><strong>دامنه (برای سرور ایران)</strong>: دامنه‌ای که به IP سرور resolve بشه (Cloudflare Proxy باید خاموش باشه)</li>
            </ul>
        </section>

        <section id="installation">
            <h2>نصب</h2>
            <p>برای نصب <strong>پخشش کن!</strong>، دستور زیر رو توی ترمینال سرور اجرا کنید:</p>
            <pre><code>bash &lt;(curl -Ls https://raw.githubusercontent.com/mahdikbk/pakhshesh-kon/main/install.sh --ipv4)</code></pre>
            <h3>مراحل نصب</h3>
            <ol>
                <li><strong>انتخاب گزینه</strong>: یکی از گزینه‌های زیر رو انتخاب کنید:
                    <ul>
                        <li><code>1) Install Pakhshesh Kon</code>: نصب پنل و V2Ray</li>
                        <li><code>2) Uninstall Pakhshesh Kon</code>: حذف کامل پنل و فایل‌ها</li>
                        <li><code>3) Exit</code>: خروج از اسکریپت</li>
                    </ul>
                </li>
                <li><strong>نوع سرور</strong>: انتخاب کنید سرور <strong>ایران</strong> یا <strong>خارجی</strong> است:
                    <ul>
                        <li><strong>ایران</strong>: نیاز به دامنه (مثل <code>iran.doregi.ir</code>) و مسیر URL (مثل <code>kbkpanel</code>) داره.</li>
                        <li><strong>خارجی</strong>: فقط نام سرور (مثل <code>Finland-1</code>) نیازه.</li>
                    </ul>
                </li>
                <li><strong>وارد کردن اطلاعات</strong>:
                    <ul>
                        <li>برای سرور ایران: نام کاربری ادمین، رمز، دامنه، و مسیر URL.</li>
                        <li>برای سرور خارجی: نام سرور.</li>
                    </ul>
                </li>
                <li><strong>اتمام نصب</strong>: اسکریپت همه‌چیز (V2Ray، Apache، دیتابیس، و پنل) رو نصب می‌کنه و اطلاعات نهایی رو نمایش می‌ده.</li>
            </ol>
            <h3>خروجی نمونه</h3>
            <pre><code>
Setup finished successfully!
Access your panel at: https://iran.doregi.ir/kbkpanel/
V2Ray is running on port: 10062
Admin Username: admin
Admin Password: [Your chosen password]
Installation logs and summary saved in /var/log/pakhsheshkon.log and /var/log/pakhsheshkon_install_summary.txt
Thank you for using Pakhshesh Kon by MahdiKBK!
            </code></pre>
        </section>

        <section id="usage">
            <h2>راهنمای استفاده</h2>
            <h3>ورود به پنل</h3>
            <ol>
                <li>به آدرس پنل (مثل <code>https://iran.doregi.ir/kbkpanel/</code>) برید.</li>
                <li>با نام کاربری و رمز ادمین (مثل <code>admin</code>) وارد بشید.</li>
                <li>داشبورد با نمودارهای واقعی ترافیک، پینگ، و کاربران فعال رو ببینید.</li>
            </ol>
            <h3>مدیریت کاربران</h3>
            <ul>
                <li><strong>ایجاد کاربر</strong>:
                    <ul>
                        <li>به بخش <strong>کاربران</strong> برید.</li>
                        <li>اطلاعات (نام کاربری، ترافیک، تعداد اتصال، روز، گروه سرور) رو وارد کنید.</li>
                        <li>لینک V2Ray و QR کد برای کاربر تولید می‌شه.</li>
                    </ul>
                </li>
                <li><strong>دانلود گروهی</strong>: لینک‌های همه کاربران رو به‌صورت ZIP دانلود کنید.</li>
            </ul>
            <h3>مدیریت سرورها</h3>
            <ul>
                <li><strong>اضافه کردن سرور خارجی</strong>:
                    <ul>
                        <li>کد رمزنگاری‌شده سرور خارجی (تولیدشده توسط اسکریپت روی سرور خارجی) رو وارد کنید.</li>
                        <li>گروه سرور (مثل اروپا) رو انتخاب کنید.</li>
                    </ul>
                </li>
                <li><strong>مانیتورینگ</strong>: وضعیت سرورها (پینگ، ترافیک، کاربران فعال) رو در بخش <strong>مانیتورینگ</strong> ببینید.</li>
            </ul>
            <h3>آپدیت پنل</h3>
            <ul>
                <li>به بخش <strong>به‌روزرسانی</strong> برید و روی دکمه <strong>به‌روزرسانی از گیت‌هاب</strong> کلیک کنید.</li>
                <li>پنل به‌صورت خودکار از مخزن گیت‌هاب آپدیت می‌شه.</li>
            </ul>
        </section>

        <section id="file-structure">
            <h2>ساختار فایل‌ها</h2>
            <pre><code>
pakhshesh-kon/
├── assets/
│   ├── css/
│   │   └── style.css         # استایل‌های CSS و انیمیشن‌ها
│   ├── js/
│   │   └── script.js         # اسکریپت‌های جاوااسکریپت (مانیتورینگ و تم)
│   └── fonts/
│       └── Yekan.ttf         # فونت یکان
├── includes/
│   ├── auth.php             # مدیریت احراز هویت
│   ├── db.php               # اتصال به دیتابیس
│   ├── functions.php        # توابع اصلی (ایجاد کاربر، لود بالانسینگ)
│   ├── server-key.php       # مدیریت کدهای رمزنگاری سرور
│   ├── config.php           # تنظیمات دیتابیس و BASE_URL
│   └── nav.php              # منوی ناوبری
├── qrcodes/                 # ذخیره QR کدهای کاربران
├── index.php                # صفحه ورود
├── dashboard.php            # داشبورد با نمودارهای واقعی
├── users.php                # مدیریت کاربران
├── servers.php              # مدیریت سرورها
├── server-groups.php        # مدیریت گروه‌های سرور
├── monitoring.php           # مانیتورینگ سرورها
├── tickets.php              # سیستم تیکت پشتیبانی
├── logs.php                 # لاگ‌های سیستم
├── update.php               # آپدیت پنل با AJAX
├── ping.php                 # تست پینگ سرورها
├── monitor.php              # دریافت داده‌های مانیتورینگ
└── .htaccess                # تنظیمات Apache
            </code></pre>
        </section>

        <section id="troubleshooting">
            <h2>لاگ‌ها و عیب‌یابی</h2>
            <p>لاگ‌ها و خلاصه نصب توی این مسیرها ذخیره می‌شن:</p>
            <ul>
                <li><strong>لاگ‌های نصب</strong>: <code>/var/log/pakhsheshkon.log</code></li>
                <li><strong>خلاصه نصب</strong>: <code>/var/log/pakhsheshkon_install_summary.txt</code></li>
            </ul>
            <h3>رفع خطاهای رایج</h3>
            <ol>
                <li><strong>خطای 500</strong>:
                    <ul>
                        <li>لاگ‌های Apache رو چک کنید:
                            <pre><code>cat /var/log/apache2/pakhsheshkon-error.log
cat /var/log/apache2/pakhsheshkon-ssl-error.log</code></pre>
                        </li>
                        <li>مطمئن بشید ماژول <code>pdo_mysql</code> نصب شده:
                            <pre><code>php -m | grep pdo_mysql</code></pre>
                        </li>
                        <li>دسترسی‌های فایل‌ها رو بررسی کنید:
                            <pre><code>ls -l /var/www/html/kbkpanel/</code></pre>
                        </li>
                    </ul>
                </li>
                <li><strong>فونت لود نمی‌شه</strong>:
                    <ul>
                        <li>چک کنید فونت یکان دانلود شده:
                            <pre><code>ls -l /var/www/html/kbkpanel/assets/fonts/Yekan.ttf</code></pre>
                        </li>
                    </ul>
                </li>
                <li><strong>مشکل دیتابیس</strong>:
                    <ul>
                        <li>اتصال دیتابیس رو تست کنید:
                            <pre><code>mysql -u pkuser_xxx -p -e "SELECT 1" pk_xxx</code></pre>
                            (مقادیر <code>pkuser_xxx</code> و <code>pk_xxx</code> رو از <code>/var/log/pakhsheshkon_install_summary.txt</code> بگیرید).
                        </li>
                    </ul>
                </li>
            </ol>
        </section>

        <section id="future-ideas">
            <h2>ایده‌های آینده</h2>
            <ul>
                <li><strong>ادغام با اپلیکیشن موبایل</strong>: توسعه اپلیکیشن برای مدیریت پنل.</li>
                <li><strong>هشدارهای ایمیل</strong>: ارسال اعلان‌های ایمیلی برای ادمین‌ها.</li>
                <li><strong>پشتیبانی از پروتکل‌های جدید</strong>: مثل WireGuard.</li>
                <li><strong>پشتیبانی از چند دامنه</strong>: مدیریت چندین دامنه در یک پنل.</li>
                <li><strong>تحلیل ترافیک پیشرفته</strong>: نمایش جزئیات ترافیک به‌صورت ساعتی/روزانه/ماهانه.</li>
            </ul>
        </section>

        <section id="contributing">
            <h2>مشارکت</h2>
            <p>ما از مشارکت شما استقبال می‌کنیم! برای گزارش باگ یا پیشنهاد قابلیت جدید:</p>
            <ol>
                <li>یه <strong>Issue</strong> توی گیت‌هاب باز کنید: <a href="https://github.com/mahdikbk/pakhshesh-kon/issues">GitHub Issues</a></li>
                <li>برای تغییرات، یه <strong>Pull Request</strong> بفرستید.</li>
            </ol>
        </section>

        <section id="license">
            <h2>لایسنس</h2>
            <p>این پروژه تحت <a href="https://opensource.org/licenses/MIT">لایسنس MIT</a> منتشر شده. شما می‌تونید آزادانه از این کد استفاده، تغییر، یا توزیع کنید.</p>
        </section>
    </div>

    <footer>
        <p>ساخته شده با ❤️ توسط <strong>MahdiKBK</strong>.</p>
        <p>از همه کاربران و مشارکت‌کنندگان تشکر می‌کنیم که <strong>پخشش کن!</strong> رو به یه پروژه خفن تبدیل کردن!</p>
    </footer>
</body>
</html>
