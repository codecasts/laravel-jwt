<?php

namespace Kino\Auth\JWT\Auth;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Kino\Auth\JWT\Contracts\Auth\Guard as GuardContract;

/**
 * JWT Guard class.
 *
 * This class is responsible for actually authenticating requests that
 * comes with a token (or denying those without a token or with a
 * invalid one).
 */
class Guard implements GuardContract
{
    // this trait bootstrap some common guard methods
    // so we just need to implement a few ones.
    use GuardHelpers;

    /**
     * @var \Illuminate\Contracts\Foundation\Application
     */
    protected $app;

    /**
     * Guard / Provider name.
     *
     * @var string
     */
    protected $name;

    /**
     * The currently authenticated user.
     *
     * @var \Illuminate\Contracts\Auth\Authenticatable
     */
    protected $user;

    /**
     * The user provider implementation.
     *
     * @var \Illuminate\Contracts\Auth\UserProvider
     */
    protected $provider;


    /**
     * The token manager implementation.
     *
     * @var \Kino\Auth\JWT\Contracts\Token\Manager
     */
    protected $manager;

    /**
     * Used to allow checks just after logout.
     *
     * In a JWT scenario, logged out means there was an explicit action
     * to log out the user and the token has been blacklisted.
     *
     * @var bool
     */
    protected $loggedOut = false;

    /**
     * JWT Guard constructor.
     *
     * @param \Illuminate\Contracts\Foundation\Application $app
     * @param string $name
     * @param \Illuminate\Contracts\Auth\UserProvider $provider
     * @param \Kino\Auth\JWT\Contracts\Token\Manager $manager
     */
    public function __construct($app, $name, $provider, $manager)
    {
        // assign constructor arguments into instance scope.
        $this->app = $app;
        $this->name = $name;
        $this->provider = $provider;
        $this->manager = $manager;
    }

    public function validate(array $credentials = [])
    {
        // TODO: Implement validate() method.
    }

    /**
     * Attempt to authenticate a user using the given credentials.
     *
     * @param  array  $credentials
     * @param  bool   $remember
     * @return bool
     */
    public function attempt(array $credentials = [], $remember = false)
    {
//        $this->fireAttemptEvent($credentials, $remember);
//
//        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);
//
//        // If an implementation of UserInterface was returned, we'll ask the provider
//        // to validate the user against the given credentials, and if they are in
//        // fact valid we'll log the users into the application and return true.
//        if ($this->hasValidCredentials($user, $credentials)) {
//            $this->login($user, $remember);
//
//            return true;
//        }
//
//        // If the authentication attempt fails we will fire an event so that the user
//        // may be notified of any suspicious attempts to access their account from
//        // an unrecognized user. A developer may listen to this event as needed.
//        $this->fireFailedEvent($user, $credentials);
//
//        return false;
    }

    /**
     * Login a given user. It means, generate a new token for a user.
     *
     * @param Authenticatable $user
     * @param array $customClaims
     * @return mixed
     */
    public function login(Authenticatable $user, array $customClaims = [])
    {
        // try to generate a new token for the user.
        $token = $this->manager->issue($user, $customClaims);

        if ($token) {
            // set current user as authenticated.
            $this->setUser($user);
            // returns the recently generated token.
            return $token;
        }

        // no token could be generated.
    }

    public function user()
    {
        // if the user was explicitly marked as logged out.
        if ($this->loggedOut) {
            // just return null.
            return null;
        }

        /** @var Request $request */
        $request = $this->app->request;

        // if there is no Authorization header on the request.
        if (!$request->headers->has('Authorization')) {
            // also return null since no user can be determined.
            return null;
        }

        // gets the authorization header from the request.
        $header = $request->headers->get('Authorization');

        // gets the token part of the authorization header, as string.
        $tokenString = Str::replaceFirst('Bearer ', '', $header);

        // parse the string token into a Token object
        $token = $this->manager->parseToken($tokenString);

        // if the received token is not actually valid.
        if (!$this->manager->validToken($token)) {
            // also return null since the token
            // signature could not be determined.
            return null;
        }

        // if the token has expired.
        if ($this->manager->expired($token)) {
            // you got right?
            return null;
        }

        // retrieves the user ID from the token.
        $id = $token->getClaim('sub');

        // use the users provider to find the token subject (user)
        // but it's id (subject)
        $user = $this->provider->retrieveById($id);

        // if the user has not been found.
        if (!$user) {
            // abort!
            return null;
        }

        // set the current user on the scope.
        $this->setUser($user);

        // return the scope user.
        return $this->user;
    }

    /**
     * Log the user out of the application.
     *
     * @return void
     */
    public function logout()
    {
        $user = $this->user();

        // blacklist the user token.

        $this->loggedOut = true;
    }
}