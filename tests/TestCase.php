<?php

namespace Tests;

use Codecasts\Auth\JWT\ServiceProvider;

class TestCase extends \Orchestra\Testbench\TestCase
{
    public function getPackageProviders()
    {
        return [ServiceProvider::class, AuthService::class];
    }
}
