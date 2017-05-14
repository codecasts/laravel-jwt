<?php

namespace Kino\Auth\JWT\Contracts\Auth;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard as LaravelGuard;

interface Guard extends LaravelGuard
{
    /**
     * JWT Guard constructor.
     *
     * @param \Illuminate\Contracts\Foundation\Application $app
     * @param string $name
     * @param \Illuminate\Contracts\Auth\UserProvider $provider
     * @param \Kino\Auth\JWT\Contracts\Token\Manager $manager
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
}