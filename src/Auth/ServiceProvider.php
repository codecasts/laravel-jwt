<?php

namespace Kino\Auth\JWT\Auth;

use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Foundation\Support\Providers\AuthServiceProvider;
use Kino\Auth\JWT\Contracts\Token\Manager as TokenManager;
use Illuminate\Auth\AuthManager;

/**
 * Service provider to register the 'jwt' auth guard.
 */
class ServiceProvider extends AuthServiceProvider
{
    /**
     * Laravel auth manager that will be needed to register the guard.
     *
     * @var AuthManager
     */
    protected $authManager = null;

    /**
     * Boot Guard.
     */
    public function boot()
    {
        // gets the auth factory instance and register on provider attribute.
        $this->authManager = $this->app->make(AuthManager::class);

        // register auth policies.
        $this->registerPolicies();

        // define a "jwt" guard.
        $this->authManager->extend('jwt', function ($app, $name, array $config) {
            // gets a instance of the token manager
            $tokenManager = $this->getTokenManager();

            // gets a instance of the user provider
            $userProvider = $this->getUserProvider($config['provider']);

            // returns a new guard instance passing a provider and a token manager
            return new Guard($app, $name, $userProvider, $tokenManager);
        });
    }

    /**
     * Get's the configured user provider instance.
     *
     * @param $alias
     * @return UserProvider
     */
    protected function getUserProvider($alias)
    {
        return $this->authManager->createUserProvider($alias);
    }

    /**
     * Get's a instance of the token manager.
     *
     * @return \Kino\Auth\JWT\Contracts\Token\Manager
     */
    protected function getTokenManager()
    {
        return $this->app->make(TokenManager::class);
    }
}