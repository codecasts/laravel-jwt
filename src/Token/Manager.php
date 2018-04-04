<?php

namespace Codecasts\Auth\JWT\Token;

use Carbon\Carbon;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Config\Repository as Config;
use Illuminate\Cache\Repository as Cache;
use Illuminate\Support\Str;
use Codecasts\Auth\JWT\Contracts\Token\Manager as ManagerContract;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Token;

/**
 * JWT Token Manager.
 */
class Manager implements ManagerContract
{
    /**
     * @var \Illuminate\Config\Repository
     */
    protected $config;

    /**
     * @var \Illuminate\Cache\Repository
     */
    protected $cache;

    /**
     * JWT Issuer (API Hostname).
     *
     * @var String
     */
    protected $issuer;

    /**
     * Secret that will be used to sign tokens.
     *
     * @var string
     */
    protected $secret = null;

    /**
     * Token time to live (TTL, in minutes).
     *
     * @var int
     */
    protected $ttl = 60;

    /**
     * Refresh after expired limit (in minutes).
     *
     * @var int
     */
    protected $refreshLimit = 7200;

    /**
     * JWT Builder.
     *
     * @var \Lcobucci\JWT\Builder
     */
    protected $builderClass = Builder::class;

    /**
     * JWT Parser Class.
     *
     * @var \Lcobucci\JWT\Parser
     */
    protected $parserClass = Parser::class;

    /**
     * JWT HMAC-SHA256 Signer.
     *
     * @var \Lcobucci\JWT\Signer\Hmac\Sha256
     */
    protected $signerClass = Sha256::class;

    /**
     * Token Manager constructor.
     *
     * @param \Illuminate\Config\Repository  $config
     * @param \Illuminate\Cache\Repository   $cache
     */
    public function __construct(Config $config, Cache $cache)
    {
        // setup repositories.
        $this->config = $config; //config repository.
        $this->cache = $cache;   // cache repository.

        // setup the secret that will be used to sign keys.
        $this->setupSecret();

        // setup other config resources.
        $this->setupConfig();
    }

    /**
     * Setup the secret that will be used to sign keys.
     */
    public function setupSecret()
    {
        // gets the key from config.
        $secret = $this->config->get('jwt.secret');

        // if the secret is in a base64 format, unwrap it's value
        if (Str::startsWith($secret, 'base64:')) {
            // remove the 'base64:' part and decode the value.
            $secret = base64_decode(substr($secret, 7));
        }

        // set the secret on the local scope.
        $this->secret = $secret;

        // if the secret is not valid,
        // throw an exception to avoid continuing.
        if (!$this->validSecret()) {
            throw new \Exception('Invalid Secret (not present or too short). Use php artisan jwt:generate to create a valid key.');
        }
    }

    /**
     * Determines if the current secret is valid and secure enough.
     * Of course it will only check for size since there's no way
     * (that I know of) of check if a value is really random.
     *
     * @return bool
     */
    protected function validSecret()
    {
        // this method is intentionally broken in two pieces
        // so the logic will be loud and clear.

        // is the secret empty?
        if (empty($this->secret)) {
            return false;
        }

        // created a hex representation of the secret.
        $hexRepresentation = bin2hex($this->secret);

        // check for the secret's hex representation length...
        // hex size is deterministic, it's a way of counting bytes from binary
        // ( SORT OF)
        // in any case, the length will double of the binary random generated secret.
        // 16 bytes secret will have a hex of length 32
        // 32 bytes secret will have a hex of length 64
        // 64 bytes secret will have a hex of length 128
        // you get it right?
        if ((Str::length($hexRepresentation) / 2) < 16) {
            // the minimum secret size should be 16
            // so return false in case the secret
            // is shorter than that.
            return false;
        }

        // after all this checks, declare the secret valid (finally).
        return true;
    }

    /**
     * Setup JWT configuration.
     */
    protected function setupConfig()
    {
        // setup time to live (in minutes), defaults to 60.
        $this->ttl = $this->config->get('jwt.ttl', 60);

        // setup refresh limit (in minutes), defaults to 7200 (5 days)
        $this->refreshLimit = $this->config->get('jwt.refresh_limit', 7200);

        // set the token issuer (domain name).
        $this->issuer = url('');
    }

    /**
     * Returns a new Signer instance.
     *
     * @return Sha256
     */
    protected function signer()
    {
        return app()->make($this->signerClass);
    }

    /**
     * Returns a new Builder instance.
     *
     * @return Builder
     */
    protected function builder()
    {
        return app()->make($this->builderClass);
    }

    /**
     * Returns a new Parser instance.
     *
     * @return Parser
     */
    protected function parser()
    {
        return app()->make($this->parserClass);
    }

    /**
     * Create a carbon object with current time and date.
     * @return Carbon
     */
    protected function now()
    {
        return Carbon::now('UTC');
    }

    /**
     * Generates a random short ID to be used as the token id.
     *
     * This id is actually used only for blacklisting the tokens, not need for
     * additional security.
     *
     * @return string
     */
    protected function generateId()
    {
        return Str::random(16);
    }

    /**
     * @param Authenticatable $user
     * @param array $additionalCustomClaims
     *
     * @return string
     */
    public function issue(Authenticatable $user, array $additionalCustomClaims = [])
    {
        // gets a new builder instance.
        $builder = $this->builder();

        // set the issued
        $builder->setIssuer($this->issuer);

        // set the subject.
        $builder->setSubject($user->getAuthIdentifier());

        // generate a unique id for the token, and set it to replicate as a header.
        $builder->setId($this->generateId(), true);

        // detect what time is it.
        $now = $this->now();

        // set issue date.
        $builder->setIssuedAt($now->timestamp);

        // set the token cannot be used before now.
        $builder->setNotBefore($now->timestamp);

        // calculate and set the expiration date for the token.
        $expiresAt = (clone $now)->addMinutes($this->ttl);
        $builder->setExpiration($expiresAt->timestamp);

        // created a custom claim that informs the limit time
        // for the token to be renewed.
        // the refresh limit is based on ttl + limit (grace period).
        $refreshLimit = (clone $now)->addMinutes($this->ttl + $this->refreshLimit);
        $builder->set('rli', $refreshLimit->timestamp);

        // loop through custom claims.
        foreach($additionalCustomClaims as $claim => $value) {
            // set custom claim.
            $builder->set($claim, $value);
        }

        // set user object default custom claims.
        if (method_exists($user, 'customJWTClaims')) {
            // call the methods.
            try {
                // call the custom claims method.
                $customClaims = (array) $user->customJWTClaims();

                // if the custom claims method returns a array.
                foreach($customClaims as $claim => $value) {
                    $builder->set($claim, $value);
                }
            } catch(\Exception $e) {
                // just continue since the custom claims should
                // not prevent the token of being issued.
            }
        }

        // get the signer.
        $signer = $this->signer();

        // sign the configure token.
        $builder->sign($signer, $this->secret);

        // gets the actual signed token as string.
        $token = (string) $builder->getToken();

        // returns the token.
        return $token;
    }

    /**
     * Verify the signature of a given token object.
     *
     * @param Token $token
     * @return bool
     */
    protected function verify(Token $token)
    {
        // the verification is made against the secret key.
        // this will not check of expiration, only for signature checking.
        return $token->verify($this->signer(), $this->secret);
    }

    /**
     * Method for parsing a token from a string.
     *
     * @param string $tokenString
     *
     * @return Token
     */
    public function parseToken(string $tokenString)
    {
        // try to parse a token string.
        try {
            return $this->parser()->parse($tokenString);
        } catch (\Exception $e) {
            // if it was not possible to, return null.
            return null;
        }
    }

    /**
     * Detects if a given token is valid or not.
     *
     * @param Token $token
     *
     * @return bool
     */
    public function validToken(Token $token)
    {
        return $this->verify($token);
    }

    /**
     * Detects if a given token is Invalid.
     *
     * @param Token $token
     * @return bool
     */
    public function invalidToken(Token $token)
    {
        return !$this->validToken($token);
    }

    /**
     * Is the token Expired?
     *
     * @param Token $token
     * @return bool
     */
    public function expired(Token $token)
    {
        return $token->isExpired();
    }

    /**
     * Is the token Expired?
     *
     * @param Token $token
     * @return bool
     */
    public function canBeRenewed(Token $token)
    {
        if(!$token->isExpired()) {
            return true;
        }

        // get the renewal limit from token.
        $renewalLimitTimestamp = $token->getClaim('rli', null);

        // if no renewal limit exists, it means
        // that it should not be renewed.
        if (!$renewalLimitTimestamp) {
            return false;
        }

        // created a UTC carbon object using the renewal limit.
        $limit = Carbon::createFromTimestampUTC($renewalLimitTimestamp);

        // get a UTC carbon object that represents now.
        $now = $this->now();

        // return true if now if before the limit.
        return $now->lessThanOrEqualTo($limit);
    }
}
