<?php

namespace Kino\Auth\JWT;

use Illuminate\Support\ServiceProvider as LaravelServiceProvider;
use Kino\Auth\JWT\Auth\Guard;
use Kino\Auth\JWT\Console\KeyGenerateCommand;
use Kino\Auth\JWT\Contracts;
use Kino\Auth\JWT\Token\Manager;
use Kino\Auth\JWT\Auth\ServiceProvider as AuthServiceProvider;

/**
 * Kino JWT Auth for Laravel 5.4
 *
 * Main Service provider.
 */
class ServiceProvider extends LaravelServiceProvider
{
    /**
     * Yes, the base class already has $defer as false.
     * But in case the Laravel API changes that in the future,
     * this attribute makes sure that this provider cannot be deferred.
     *
     * @var bool
     */
    protected $defer = false;

    /**
     * Boots the Service provider.
     */
    public function boot()
    {
        // declare the configuration files available for publishing.
        $this->publishes([__DIR__.'../config/jwt.php'], 'config');
    }


    public function register()
    {
        // register contract/concrete bindings.
        $this->registerBindings();

        // register commands.
        $this->registerCommands();

        // register the "auth" service provider.
        // this is needed in order because that service
        // provider needs to inherit from the Laravel
        // default service provider, which register policies
        // and other resources that are not possible (at least harder)
        // to do in a common service provider.
        $this->app->register(AuthServiceProvider::class);
    }

    /**
     * Binds Contracts (interfaces) and Concretes (implementations) together.
     */
    protected function registerBindings()
    {
        // bind the manager class.
        $this->app->bind(Contracts\Token\Manager::class, Manager::class);

        // bind the guard class.
        $this->app->bind(Contracts\Auth\Guard::class, Guard::class);
    }

    /**
     * Register console commands this package provides.
     */
    protected function registerCommands()
    {
        $this->commands([
            KeyGenerateCommand::class, // "jwt:generate" command (generates keys).
        ]);
    }
}