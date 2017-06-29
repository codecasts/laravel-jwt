<?php

namespace Codecasts\Auth\JWT;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Routing\Events\RouteMatched;
use Illuminate\Support\Arr;
use Illuminate\Support\ServiceProvider as LaravelServiceProvider;
use Codecasts\Auth\JWT\Auth\Guard;
use Codecasts\Auth\JWT\Console\KeyGenerateCommand;
use Codecasts\Auth\JWT\Contracts;
use Codecasts\Auth\JWT\Token\Manager;
use Codecasts\Auth\JWT\Auth\ServiceProvider as AuthServiceProvider;

/**
 * Codecasts JWT Auth for Laravel 5.4
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
        $this->publishes([
            __DIR__.'/../config/jwt.php' => config_path('jwt.php')
        ]);

        // case enabled, setups a guard match by middleware group name.
        $this->setupGuardMiddlewareMatch();
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
            // "jwt:generate" command (generates keys).
            KeyGenerateCommand::class,
        ]);
    }

    /**
     * Setup the current guard to be matched by route middleware name.
     */
    protected function setupGuardMiddlewareMatch()
    {
        // should the middleware group match the guard name?
        $middlewareMatch = $this->app['config']->get('jwt.middleware_match', true);

        if ($middlewareMatch) {
            // when the route is actually matched...
            $this->app['router']->matched(function (RouteMatched $event) {

                // get the route middleware group.
                $middlewareGroup = Arr::first((array) $event->route->middleware());

                // if there is a group detected and  there is a guard that matches the middleware
                // group name...
                if ($middlewareGroup && !!$this->app['auth']->guard($middlewareGroup)) {
                    // setup the matching guard as default.
                    $this->app['auth']->setDefaultDriver($middlewareGroup);
                }
            });
        }
    }
}
