<?php

namespace Codecasts\Auth\JWT\Auth;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Events\Dispatcher;
use Symfony\Component\HttpFoundation\Request;
use Illuminate\Support\Str;
use Codecasts\Auth\JWT\Contracts\Auth\Guard as GuardContract;
use Lcobucci\JWT\Token;

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
     * @var \Codecasts\Auth\JWT\Contracts\Token\Manager
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
     * The event dispatcher instance.
     *
     * @var \Illuminate\Contracts\Events\Dispatcher
     */
    protected $events;

    /**
     * The current Request;
     *
     * @var \Symfony\Component\HttpFoundation\Request
     */
    protected $request;

    /**
     * The user we last attempted to retrieve.
     *
     * @var \Illuminate\Contracts\Auth\Authenticatable
     */
    protected $lastAttempted;

    /**
     * The detected JWT token.
     *
     * @var Token|null
     */
    protected $token = null;

    /**
     * JWT Guard constructor.
     *
     * @param \Illuminate\Contracts\Foundation\Application $app
     * @param string $name
     * @param \Illuminate\Contracts\Auth\UserProvider $provider
     * @param \Codecasts\Auth\JWT\Contracts\Token\Manager $manager
     */
    public function __construct($app, $name, $provider, $manager)
    {
        // assign constructor arguments into instance scope.
        $this->app = $app;
        $this->name = $name;
        $this->provider = $provider;
        $this->manager = $manager;
    }

    /**
     * Fire the attempt event with the arguments.
     *
     * @param  array  $credentials
     * @return void
     */
    protected function fireAttemptEvent(array $credentials)
    {
        if (isset($this->events)) {
            $this->events->dispatch(new Attempting(
                $credentials, false
            ));
        }
    }

    /**
     * Fire the failed authentication attempt event with the given arguments.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable|null  $user
     * @param  array  $credentials
     * @return void
     */
    protected function fireFailedEvent($user, array $credentials)
    {
        if (isset($this->events)) {
            $this->events->dispatch(new Failed($user, $credentials));
        }
    }

    /**
     * Fire the login event if the dispatcher is set.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     *
     * @return void
     */
    protected function fireLoginEvent($user)
    {
        if (isset($this->events)) {
            $this->events->dispatch(new Login($user, false));
        }
    }

    /**
     * Validate a user's credentials.
     *
     * @param  array  $credentials
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);

        return $this->hasValidCredentials($user, $credentials);
    }

    /**
     * Attempt to authenticate a user using the given credentials.
     *
     * @param  array $credentials
     * @return bool
     */
    public function attempt(array $credentials = [])
    {
        $this->fireAttemptEvent($credentials);

        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);

        // If an implementation of UserInterface was returned, we'll ask the provider
        // to validate the user against the given credentials, and if they are in
        // fact valid we'll log the users into the application and return true.
        if ($this->hasValidCredentials($user, $credentials)) {
            $this->login($user);

            return true;
        }

        // If the authentication attempt fails we will fire an event so that the user
        // may be notified of any suspicious attempts to access their account from
        // an unrecognized user. A developer may listen to this event as needed.
        $this->fireFailedEvent($user, $credentials);

        return false;
    }

    /**
     * Determine if the user matches the credentials.
     *
     * @param  mixed  $user
     * @param  array  $credentials
     * @return bool
     */
    protected function hasValidCredentials($user, $credentials)
    {
        return ! is_null($user) && $this->provider->validateCredentials($user, $credentials);
    }

    /**
     * Login a given user. It means, generate a new token for a user.
     *
     * @param Authenticatable $user
     * @return mixed
     */
    public function login(Authenticatable $user)
    {
        // If we have an event dispatcher instance set we will fire an event so that
        // any listeners will hook into the authentication events and run actions
        // based on the login and logout events fired from the guard instances.
        $this->fireLoginEvent($user);

        $this->setUser($user);
    }

    /**
     * Parse the request looking for the authorization header.
     *
     * @return null|string
     */
    protected function getTokenFromHeader()
    {
        // if there is no authorization header present.
        if (!$this->getRequest()->headers->has('Authorization')) {
            // abort by returning null.
            return null;
        }

        // gets the full header string.
        $header = $this->getRequest()->headers->get('Authorization');

        // returns the token without the 'Bearer ' prefix.
        return Str::replaceFirst('Bearer ', '', $header);
    }

    /**
     * Parse the request looking a token as parameter.
     *
     * @return null|string
     */
    protected function getTokenFromParameter()
    {
        if (!$this->getRequest()->has('token')) {
            // abort by returning null.
            return null;
        }

        //  return the request token.
        return $this->getRequest()->get('token', null);
    }

    /**
     * @return Token|null
     */
    protected function detectedToken()
    {
        // retrieve the token from the Authorization header.
        $headerToken = $this->getTokenFromHeader();

        // if a token was found...
        if ($headerToken) {
            // return a new token instance.
            $this->token = $this->manager()->parseToken($headerToken);
        }

        // try to find a token passed as parameter on the request.
        $parameterToken = $this->getTokenFromParameter();

        // if found...
        if ($parameterToken) {
            $this->token = $this->manager()->parseToken($parameterToken);
        }

        // return null if no token could be found.
        return $this->token;
    }

    /**
     * Retrieves the user by it's token.
     *
     * @param Token $token
     * @return Authenticatable|null
     */
    protected function findUserByToken(Token $token)
    {
        // retrieves the user ID from the token.
        $id = $token->getClaim('sub');

        // use the users provider to find the token subject (user)
        // but it's id (subject)
        return $this->provider->retrieveById($id);
    }

    /**
     * Get / Detect the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function user()
    {
        // if the user was explicitly marked as logged out.
        if ($this->loggedOut) {
            // just return null.
            return null;
        }

        // if the user is already set.
        if ($this->user) {
            return $this->user;
        }

        // detects a token presence.
        $token = $this->detectedToken();

        // if the received token is not actually valid.
        if (!$token || !$this->manager->validToken($token)) {
            // also return null since the token
            // signature could not be determined.
            return null;
        }

        // if the token has expired.
        if ($this->manager->expired($token)) {
            // you got right?
            return null;
        }

        // try to find the user which the token belongs to.
        $user = $this->findUserByToken($token);

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

    /**
     * Returns the guard instance of the token manager.
     *
     * @return \Codecasts\Auth\JWT\Contracts\Token\Manager
     */
    public function manager()
    {
        return $this->manager;
    }

    /**
     * Issue a token for the current authenticated user.
     *
     * @param array $customClaims
     * @return bool|string
     */
    public function issue(array $customClaims = [])
    {
        // ensure there is a user logged in.
        if (!$this->user) {
            return false;
        }

        // try to issue a new token and return.
        try {
            return $this->manager()->issue($this->user, $customClaims);
        } catch (\Exception $e) {
            // catch any exceptions that the token issuing may trigger.
            return false;
        }
    }

    /**
     * Refresh a given token.
     *
     * @param string $token
     * @param array  $customClaims
     * @return bool|string
     */
    public function refresh(string $token = null, array $customClaims = [])
    {
        // detect token if none was passed.
        $token = $token ?? $this->detectedToken();

        // if no token was detected.
        if (!$token) {
            return false;
        }

        // if the token cannot be refreshed.
        if (!$this->manager()->canBeRenewed($token)) {
            // abort by returning false.
            return false;
        }

        // try to locate the user which the token belongs to.
        $user = $this->findUserByToken($token);

        // if not user could be found.
        if (!$user) {
            return false;
        }

        // set the user instance.
        $this->user = $user;

        // try to issue a new token and refresh
        try {
            return $this->manager()->issue($user, $customClaims);
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     * Get the event dispatcher instance.
     *
     * @return \Illuminate\Contracts\Events\Dispatcher
     */
    public function getDispatcher()
    {
        return $this->events;
    }

    /**
     * Set the event dispatcher instance.
     *
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     * @return void
     */
    public function setDispatcher(Dispatcher $events)
    {
        $this->events = $events;
    }

    /**
     * Get the current request instance.
     *
     * @return \Symfony\Component\HttpFoundation\Request
     */
    public function getRequest()
    {
        return $this->request ?: $this->app->request;
    }

    /**
     * Set the current request instance.
     *
     * @param  \Symfony\Component\HttpFoundation\Request  $request
     * @return $this
     */
    public function setRequest(Request $request)
    {
        $this->request = $request;

        return $this;
    }

    /**
     * The detected JWT token.
     *
     * @return string
     */
    public function getToken()
    {
        return $this->token;
    }

}