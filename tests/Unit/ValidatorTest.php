<?php

namespace PakhsheshKon\Tests\Unit;

use PHPUnit\Framework\TestCase;
use PakhsheshKon\Helpers\Validator;

class ValidatorTest extends TestCase
{
    public function testIP()
    {
        $this->assertTrue(Validator::ip('192.168.1.1'));
        $this->assertTrue(Validator::ip('2001:0db8:85a3:0000:0000:8a2e:0370:7334'));
        $this->assertFalse(Validator::ip('invalid'));
    }

    public function testPort()
    {
        $this->assertTrue(Validator::port(80));
        $this->assertTrue(Validator::port(65535));
        $this->assertFalse(Validator::port(0));
        $this->assertFalse(Validator::port(65536));
    }

    public function testUUID()
    {
        $validUUID = '550e8400-e29b-41d4-a716-446655440000';
        $this->assertTrue(Validator::uuid($validUUID));
        $this->assertFalse(Validator::uuid('invalid-uuid'));
    }

    public function testDomain()
    {
        $this->assertTrue(Validator::domain('example.com'));
        $this->assertTrue(Validator::domain('sub.example.com'));
        $this->assertFalse(Validator::domain('invalid domain'));
    }

    public function testPasswordStrength()
    {
        $weak = Validator::passwordStrength('123');
        $this->assertFalse($weak['is_strong']);

        $strong = Validator::passwordStrength('MyP@ssw0rd123');
        $this->assertTrue($strong['is_strong']);
    }
}

