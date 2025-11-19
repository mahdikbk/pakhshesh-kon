<?php

namespace PakhsheshKon\Controllers;

use PakhsheshKon\Core\Session;
use PakhsheshKon\Core\Security;
use PakhsheshKon\Core\Logger;
use PakhsheshKon\Models\Admin;

/**
 * کنترلر احراز هویت
 */
class AuthController
{
    /**
     * صفحه لاگین
     */
    public function login(): void
    {
        // اگر قبلاً لاگین کرده، به داشبورد برو
        if (Session::has('user_id')) {
            header('Location: /dashboard');
            exit;
        }

        $error = null;

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            // بررسی CSRF Token
            $token = $_POST['csrf_token'] ?? '';
            if (!Security::validateCSRFToken($token)) {
                $error = "خطای امنیتی. لطفاً صفحه را رفرش کنید.";
            } else {
                // بررسی Rate Limit
                if (!Security::checkRateLimit('login', 5, 300)) {
                    $error = "تعداد تلاش‌های ناموفق بیش از حد مجاز است. لطفاً 5 دقیقه صبر کنید.";
                } else {
                    $username = Security::sanitize($_POST['username'] ?? '');
                    $password = $_POST['password'] ?? '';

                    // Validation
                    if (empty($username) || empty($password)) {
                        $error = "لطفاً تمام فیلدها را پر کنید.";
                    } elseif (!Security::validateUsername($username)) {
                        $error = "نام کاربری نامعتبر است.";
                    } else {
                        $admin = Admin::login($username, $password);
                        if ($admin) {
                            Session::set('user_id', $admin->getId());
                            Session::set('username', $admin->getUsername());
                            Logger::log("Login successful", $username);
                            header('Location: /dashboard');
                            exit;
                        } else {
                            $error = "نام کاربری یا رمز عبور اشتباه است.";
                        }
                    }
                }
            }
        }

        // نمایش صفحه لاگین
        $csrfToken = Security::generateCSRFToken();
        require dirname(__DIR__, 2) . '/views/auth/login.php';
    }

    /**
     * خروج
     */
    public function logout(): void
    {
        $username = Session::get('username');
        Logger::log("Logout", $username);
        Session::destroy();
        header('Location: /login');
        exit;
    }
}

