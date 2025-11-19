<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ورود - پخشش کن!</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="/assets/css/style.css" rel="stylesheet">
</head>
<body class="bg-gradient-to-br from-blue-900 to-indigo-800 min-h-screen flex items-center">
    <div class="container mx-auto px-4">
        <div class="max-w-md mx-auto bg-white rounded-2xl shadow-xl p-8">
            <h2 class="text-3xl font-bold text-center text-gray-800 mb-6">ورود به پنل</h2>
            <?php if ($error): ?>
                <div class="bg-red-100 text-red-700 p-4 rounded-lg mb-4">
                    <?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?>
                </div>
            <?php endif; ?>
            <form method="POST" class="space-y-6">
                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                <div>
                    <label for="username" class="block text-sm font-medium text-gray-700">نام کاربری</label>
                    <input 
                        type="text" 
                        id="username" 
                        name="username" 
                        class="mt-1 block w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500" 
                        required
                        autocomplete="username"
                    >
                </div>
                <div>
                    <label for="password" class="block text-sm font-medium text-gray-700">رمز عبور</label>
                    <input 
                        type="password" 
                        id="password" 
                        name="password" 
                        class="mt-1 block w-full p-3 border border-gray-300 rounded-lg focus:ring-indigo-500 focus:border-indigo-500" 
                        required
                        autocomplete="current-password"
                    >
                </div>
                <button 
                    type="submit" 
                    class="w-full bg-indigo-600 text-white p-3 rounded-lg hover:bg-indigo-700 transition duration-300"
                >
                    ورود
                </button>
            </form>
        </div>
    </div>
</body>
</html>

