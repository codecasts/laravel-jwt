<?php

namespace Codecasts\Auth\JWT\Contracts\Auth;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard as LaravelGuard;
use Illuminate\Contracts\Events\Dispatcher;
use Codecasts\Auth\JWT\Contracts\Token\Manager;
use Symfony\Component\HttpFoundation\Request;

interface Guard extends LaravelGuard
{
    /**
     * JWT Guard constructor.
     *
     * @param \Illuminate\Contracts\Foundation\Application $app
     * @param string $name
     * @param \Illuminate\Contracts\Auth\UserProvider $provider
     * @param \Codecasts\Auth\JWT\Contracts\Token\Manager $manager
     */
    public function __construct($app, $name, $provider, $manager);

    /**
     * @param array $credentials
     * @return mixed
     */
    public function validate(array $credentials = []);

    /**
     * Attempt to authenticate a user using the given credentials.
     *
     * @param  array  $credentials
     * @return bool
     */
    public function attempt(array $credentials = []);

    /**
     * Log a user into the application.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    public function login(Authenticatable $user);

    /**
     * Log the user out of the application.
     *
     * @return void
     */
    public function logout();

    /**
     * Returns the guard instance of the token manager.
     *
     * @return Manager
     */
    public function manager();

    /**
     * Refresh a given token.
     *
     * @param string $token
     * @param array  $customClaims
     * @return bool|string
     */
    public function refresh(string $token = null, array $customClaims = []);

    /**
     * Issue a token for the current authenticated user.
     *
     * @param array $customClaims
     * @return bool|string
     */
    public function issue(array $customClaims = []);

    /**
     * Get the event dispatcher instance.
     *
     * @return \Illuminate\Contracts\Events\Dispatcher
     */
    public function getDispatcher();

    /**
     * Set the event dispatcher instance.
     *
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     * @return void
     */
    public function setDispatcher(Dispatcher $events);

    /**
     * Get the current request instance.
     *
     * @return \Symfony\Component\HttpFoundation\Request
     */
    public function getRequest();

    /**
     * Set the current request instance.
     *
     * @param  \Symfony\Component\HttpFoundation\Request  $request
     * @return $this
     */
    public function setRequest(Request $request);
}