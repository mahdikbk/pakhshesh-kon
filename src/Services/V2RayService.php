<?php

namespace PakhsheshKon\Services;

use PakhsheshKon\Core\Config;
use PakhsheshKon\Models\User;
use PakhsheshKon\Models\Server;

/**
 * سرویس مدیریت V2Ray
 */
class V2RayService
{
    /**
     * تولید لینک VLESS
     */
    public static function generateVLESSLink(User $user, Server $server, int $port): string
    {
        $domain = Config::get('APP_URL', '');
        $domain = parse_url($domain, PHP_URL_HOST) ?: $server->getIp();
        
        $link = sprintf(
            "vless://%s@%s:%d?security=tls&type=tcp#PakhsheshKon-%s",
            $user->getUUID(),
            $domain,
            $port,
            $user->getUsername()
        );

        return $link;
    }

    /**
     * تولید لینک VMess
     */
    public static function generateVMessLink(User $user, Server $server, int $port): string
    {
        // VMess نیاز به config JSON دارد
        $config = [
            'v' => '2',
            'ps' => 'PakhsheshKon-' . $user->getUsername(),
            'add' => $server->getIp(),
            'port' => (string)$port,
            'id' => $user->getUUID(),
            'aid' => '0',
            'net' => 'ws',
            'type' => 'none',
            'host' => '',
            'path' => '',
            'tls' => 'tls'
        ];

        return 'vmess://' . base64_encode(json_encode($config));
    }

    /**
     * به‌روزرسانی فایل config V2Ray
     */
    public static function updateConfig(array $clients): bool
    {
        $configPath = Config::get('V2RAY_CONFIG_PATH', '/usr/local/etc/v2ray/config.json');
        
        $config = [
            'inbounds' => [
                [
                    'port' => (int)Config::get('V2RAY_IRAN_PORT', 10062),
                    'protocol' => 'vless',
                    'settings' => [
                        'clients' => $clients,
                        'decryption' => 'none'
                    ],
                    'streamSettings' => [
                        'network' => 'tcp',
                        'security' => 'tls',
                        'tlsSettings' => [
                            'certificates' => [
                                [
                                    'certificateFile' => '/etc/letsencrypt/live/' . parse_url(Config::get('APP_URL'), PHP_URL_HOST) . '/fullchain.pem',
                                    'keyFile' => '/etc/letsencrypt/live/' . parse_url(Config::get('APP_URL'), PHP_URL_HOST) . '/privkey.pem'
                                ]
                            ]
                        ]
                    ]
                ]
            ],
            'outbounds' => [
                [
                    'protocol' => 'freedom'
                ]
            ]
        ];

        return file_put_contents($configPath, json_encode($config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) !== false;
    }
}

