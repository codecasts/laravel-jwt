<?php

namespace Codecasts\Auth\JWT\Contracts\Token;

use \Illuminate\Cache\Repository as Cache;
use \Illuminate\Config\Repository as Config;
use Illuminate\Contracts\Auth\Authenticatable;
use Lcobucci\JWT\Token;

interface Manager
{
    /**
     * Token Manager constructor.
     *
     * @param \Illuminate\Config\Repository  $config
     * @param \Illuminate\Cache\Repository   $cache
     */
    public function __construct(Config $config, Cache $cache);

    /**
     * Setup the secret that will be used to sign keys.
     */
    public function setupSecret();

    /**
     * @param Authenticatable $user
     * @param array $customClaims
     *
     * @return string
     */
    public function issue(Authenticatable $user, array $customClaims = []);

    /**
     * Method for parsing a token from a string.
     *
     * @param string $tokenString
     *
     * @return Token
     */
    public function parseToken(string $tokenString);

    /**
     * Detects if a given token is valid or not.
     *
     * @param Token $token
     *
     * @return bool
     */
    public function validToken(Token $token);

    /**
     * Detects if a given token is Invalid.
     *
     * @param Token $token
     * @return bool
     */
    public function invalidToken(Token $token);

    /**
     * Is the token Expired?
     *
     * @param Token $token
     * @return bool
     */
    public function expired(Token $token);

    /**
     * Is the token Expired?
     *
     * @param Token $token
     * @return bool
     */
    public function canBeRenewed(Token $token);
}