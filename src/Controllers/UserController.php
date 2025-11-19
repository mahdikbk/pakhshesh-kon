<?php

namespace PakhsheshKon\Controllers;

use PakhsheshKon\Core\Session;
use PakhsheshKon\Core\Security;
use PakhsheshKon\Core\Logger;
use PakhsheshKon\Models\User;
use PakhsheshKon\Models\ServerGroup;
use PakhsheshKon\Services\QRCodeService;
use PakhsheshKon\Services\V2RayService;
use PakhsheshKon\Services\TelegramService;

/**
 * کنترلر مدیریت کاربران
 */
class UserController
{
    /**
     * لیست کاربران
     */
    public function index(): void
    {
        if (!Session::has('user_id')) {
            header('Location: /login');
            exit;
        }

        $users = User::all();
        $groups = ServerGroup::all();
        $csrfToken = Security::generateCSRFToken();

        require dirname(__DIR__, 2) . '/views/users/index.php';
    }

    /**
     * ایجاد کاربر جدید
     */
    public function create(): void
    {
        if (!Session::has('user_id')) {
            header('Location: /login');
            exit;
        }

        $error = null;
        $success = null;

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            // بررسی CSRF
            if (!Security::validateCSRFToken($_POST['csrf_token'] ?? '')) {
                $error = "خطای امنیتی. لطفاً صفحه را رفرش کنید.";
            } else {
                $username = Security::sanitize($_POST['username'] ?? '');
                $trafficLimit = (int)($_POST['traffic_limit'] ?? 0);
                $connectionLimit = (int)($_POST['connection_limit'] ?? 1);
                $days = (int)($_POST['days'] ?? 30);
                $groupId = (int)($_POST['group_id'] ?? 1);

                // Validation
                if (empty($username)) {
                    $error = "نام کاربری الزامی است.";
                } elseif (!Security::validateUsername($username)) {
                    $error = "نام کاربری نامعتبر است.";
                } elseif (User::findByUsername($username)) {
                    $error = "این نام کاربری قبلاً استفاده شده است.";
                } elseif ($trafficLimit <= 0) {
                    $error = "محدودیت ترافیک باید بیشتر از صفر باشد.";
                } elseif ($connectionLimit <= 0) {
                    $error = "تعداد اتصال باید بیشتر از صفر باشد.";
                } elseif ($days <= 0) {
                    $error = "مدت زمان باید بیشتر از صفر باشد.";
                } else {
                    try {
                        // پیدا کردن بهترین سرور
                        $servers = \PakhsheshKon\Models\Server::findByGroup($groupId);
                        if (empty($servers)) {
                            $error = "هیچ سرور فعالی در این گروه وجود ندارد.";
                        } else {
                            $server = $servers[0]; // یا الگوریتم Load Balancing
                            $port = (int)\PakhsheshKon\Core\Config::get('V2RAY_IRAN_PORT', 10062);

                            // ایجاد کاربر
                            $user = User::create($username, $trafficLimit, $connectionLimit, $days, $groupId);

                            // تولید لینک V2Ray
                            $link = V2RayService::generateVLESSLink($user, $server, $port);
                            
                            // تولید QR کد
                            $qrPath = QRCodeService::generate($link, $user->getUsername() . '.png');

                            // ذخیره لینک و QR
                            $user->setLink($link);
                            $user->setQrPath($qrPath);
                            $user->save();

                            Logger::log("User created: {$username}", Session::get('username'));
                            $success = "کاربر با موفقیت ایجاد شد!";
                        }
                    } catch (\Exception $e) {
                        Logger::error("User creation failed", ['error' => $e->getMessage()]);
                        $error = "خطا در ایجاد کاربر: " . $e->getMessage();
                    }
                }
            }
        }

        $groups = ServerGroup::all();
        $csrfToken = Security::generateCSRFToken();
        require dirname(__DIR__, 2) . '/views/users/create.php';
    }

    /**
     * حذف کاربر
     */
    public function delete(): void
    {
        if (!Session::has('user_id')) {
            header('Location: /login');
            exit;
        }

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $id = (int)($_POST['id'] ?? 0);
            $user = User::findById($id);

            if ($user) {
                // حذف QR کد
                if ($user->getQrPath()) {
                    QRCodeService::delete(basename($user->getQrPath()));
                }

                $user->delete();
                Logger::log("User deleted: {$user->getUsername()}", Session::get('username'));
            }
        }

        header('Location: /users');
        exit;
    }

    /**
     * دانلود لینک‌های گروهی
     */
    public function downloadLinks(): void
    {
        if (!Session::has('user_id')) {
            header('Location: /login');
            exit;
        }

        $groupId = (int)($_GET['group_id'] ?? 0);
        
        if ($groupId) {
            $users = User::findByGroup($groupId);
        } else {
            $users = User::all();
        }

        $zipFile = tempnam(sys_get_temp_dir(), 'pakhshesh_links_');
        $zip = new \ZipArchive();
        
        if ($zip->open($zipFile, \ZipArchive::CREATE) === TRUE) {
            foreach ($users as $user) {
                if ($user->getLink()) {
                    $zip->addFromString($user->getUsername() . '.txt', $user->getLink());
                }
            }
            $zip->close();
        }

        header('Content-Type: application/zip');
        header('Content-Disposition: attachment; filename="pakhshesh_links_' . date('Y-m-d') . '.zip"');
        readfile($zipFile);
        unlink($zipFile);
        exit;
    }
}

