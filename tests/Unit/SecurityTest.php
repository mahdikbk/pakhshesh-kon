<?php

namespace PakhsheshKon\Tests\Unit;

use PHPUnit\Framework\TestCase;
use PakhsheshKon\Core\Security;

class SecurityTest extends TestCase
{
    public function testGenerateCSRFToken()
    {
        $token = Security::generateCSRFToken();
        $this->assertNotEmpty($token);
        $this->assertEquals(64, strlen($token)); // 32 bytes = 64 hex chars
    }

    public function testValidateCSRFToken()
    {
        $token = Security::generateCSRFToken();
        $this->assertTrue(Security::validateCSRFToken($token));
        $this->assertFalse(Security::validateCSRFToken('invalid_token'));
    }

    public function testSanitize()
    {
        $input = '<script>alert("XSS")</script>';
        $sanitized = Security::sanitize($input);
        $this->assertStringNotContainsString('<script>', $sanitized);
    }

    public function testValidateEmail()
    {
        $this->assertTrue(Security::validateEmail('test@example.com'));
        $this->assertFalse(Security::validateEmail('invalid-email'));
    }

    public function testValidateUsername()
    {
        $this->assertTrue(Security::validateUsername('testuser123'));
        $this->assertFalse(Security::validateUsername('test user'));
        $this->assertFalse(Security::validateUsername('ab'));
    }

    public function testHashPassword()
    {
        $password = 'test123';
        $hash = Security::hashPassword($password);
        $this->assertNotEmpty($hash);
        $this->assertTrue(Security::verifyPassword($password, $hash));
        $this->assertFalse(Security::verifyPassword('wrong', $hash));
    }
}

