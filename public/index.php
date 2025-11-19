<?php

/**
 * Entry Point اصلی برنامه
 */

// تنظیمات خطا
error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

// مسیرهای اصلی
define('ROOT_PATH', dirname(__DIR__));
define('PUBLIC_PATH', __DIR__);
define('SRC_PATH', ROOT_PATH . '/src');
define('VIEWS_PATH', ROOT_PATH . '/views');
define('CONFIG_PATH', ROOT_PATH . '/config');

// Autoloader
require_once ROOT_PATH . '/vendor/autoload.php';

// بارگذاری تنظیمات
use PakhsheshKon\Core\Config;
use PakhsheshKon\Core\Session;
use PakhsheshKon\Core\Security;

Config::load(ROOT_PATH . '/.env');
Session::start();

// Routing ساده
$requestUri = $_SERVER['REQUEST_URI'] ?? '/';
$baseUrl = Config::get('BASE_URL', '');
if ($baseUrl) {
    $requestUri = str_replace('/' . $baseUrl, '', $requestUri);
}

$requestUri = parse_url($requestUri, PHP_URL_PATH);
$requestUri = trim($requestUri, '/');

// Route ها
$routes = [
    '' => 'auth/login',
    'login' => 'auth/login',
    'logout' => 'auth/logout',
    'dashboard' => 'dashboard/index',
    'users' => 'users/index',
    'users/create' => 'users/create',
    'servers' => 'servers/index',
    'server-groups' => 'server-groups/index',
    'monitoring' => 'monitoring/index',
    'tickets' => 'tickets/index',
    'logs' => 'logs/index',
    'settings' => 'settings/index',
    'update' => 'update/index',
    'api/ping' => 'api/ping',
    'api/monitor' => 'api/monitor',
];

$route = $routes[$requestUri] ?? 'auth/login';

// بارگذاری Controller
list($controllerName, $action) = explode('/', $route);
$controllerClass = "PakhsheshKon\\Controllers\\" . ucfirst($controllerName) . "Controller";

if (class_exists($controllerClass)) {
    $controller = new $controllerClass();
    if (method_exists($controller, $action)) {
        $controller->$action();
    } else {
        http_response_code(404);
        die('Action not found');
    }
} else {
    // Fallback به فایل‌های قدیمی برای سازگاری
    $file = PUBLIC_PATH . '/' . ($requestUri ?: 'index.php');
    if (file_exists($file) && $file !== __FILE__) {
        require $file;
    } else {
        http_response_code(404);
        die('Page not found');
    }
}

