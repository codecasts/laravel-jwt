
![Readme Art](http://imageshack.com/a/img922/4489/tftxQ1.png)

# Laravel JWT

[![Latest Stable Version](https://poser.pugx.org/codecasts/laravel-jwt/v/stable)](https://packagist.org/packages/codecasts/laravel-jwt)
[![Total Downloads](https://poser.pugx.org/codecasts/laravel-jwt/downloads)](https://packagist.org/packages/codecasts/laravel-jwt)
[![License](https://poser.pugx.org/codecasts/laravel-jwt/license)](https://packagist.org/packages/codecasts/laravel-jwt)

This package provides out-of-the-box API authentication using JWT for Laravel.

## Installation.

You can install this package by running:

```bash
composer require codecasts/laravel-jwt
```

## Setup.

In order to setup this package into your application, minimal configuration
is actually needed.

### 1) Service Provider.

Register this package's Service Provider by adding it to the `providers`
section of your `config/app.php` file:

> You may skip this step on Laravel 5.5 due to the [auto-discovery package feature](https://laravel.com/docs/5.5/packages#package-discovery).

```php
   'providers' => [

       // ... other providers omitted

       Codecasts\Auth\JWT\ServiceProvider::class,

   ],
```

### 2) Configuration file.

Publish the configuration file (`config/jwt.php`) by running the
following command after registering the Service Provider.

```bash
php artisan vendor:publish --provider="Codecasts\Auth\JWT\ServiceProvider"
```

### 3) Generate a Secret.

In order for this package to works, you will need a separate secret
(do not use the application key).

This package provides a command that can be used for generating a strong key.

Get a new key by running:

```bash
php artisan jwt:generate
```

Then, copy the generated key contents into your `.env` file.

**NOTICE**: The key generation process will not automatically
set it inside your `.env` file, do it manually.

### 4) Setup Guard

In order to automatically authenticate your routes using `JWT` tokens,
you need to change the guard driver to `jwt`

Inside `config/auth.php` set the corresponding guard group you want to protect:

If you have the default guard group named `api`, your `auth.php`
should be like this:

```php
  'guards' => [
        // ... other guards omitted.

        'api' => [
            'driver'   => 'jwt', // this is the line you need to change.
            'provider' => 'users',
        ],
    ],
```

That's it, we are all ready to use it.



## Usage.

This package aims to be dead simple to use.

The following templates can be used to setup your existing
authentication controllers and resources.

**NOTICE**: Full working examples of use for this package
will be added on this package when it reaches it's 1.0 version.

### Protecting Routes.

This package is fully integrated with Laravel Authentication.

The default configuration (`config/jwt.php`) brings a sensitive value that
is very useful when your application is not completely an API: **`middleware_match`**

By not completely an API, I mean, the JWT guard is not the default one.

In those cases, in order to use the `auth` middleware, the config key
**`middleware_match`** **MUST** be set to true.

This configuration key allows non protected routes to work properly.

Notice that this option will match middleware group names with guard names.

**In this case, the 'api' middleware group will always use the `api` guard.**

**Also, the 'web' middleware group will always use the `web` guard**

If you do not use this value, you will need to use suffixes when referencing the
`auth` middleware, like `auth:api`.


### Issuing and Renewing Tokens.

For issuing tokens, no special class is actually needed,
you can just expect create a Guard current implementation from the IoC and work from there.

Check out the examples.


**On the following examples, all Guard instances are injected from `Illuminate\Contracts\Auth\Guard`**

**On the following examples, all Request instances are injected from  `Illuminate\Http\Request`**

#### Token from User Instance.

This method should be used when you just registered a user and any other
special cases.

```php

public function tokenFromUser(Guard $auth)
{
    // generating a token from a given user.
    $user = SomeUserModel::find(12);

    // logs in the user
    $auth->login($user);

    // get and return a new token
    $token = $auth->issue();

    return $token;
}

```

#### Token from User Credentials.

This method should be used when you just registered a user and any other
special cases.

```php

public function tokenFromCredentials(Guard $auth, Request $request)
{
    // get some credentials
    $credentials = $request->only(['email', 'password']);

    if ($auth->attempt($credentials)) {
       return $token = $auth->issue();
    }

    return ['Invalid Credentials'];
}

```

#### Refreshing Tokens.

Tokens can be refreshed in 2 different ways: Auto detect or manual.

If you do not pass any argument into the refresh method, the Guard will
look for either a **`Authorization`** header or a **`token`** field on the
request's body.

```php

public function refreshToken(Guard $auth)
{
    // auto detecting token from request.
    $token = $auth->refresh();

    // manually passing the token to be refreshed.
    $token = $auth->refresh($oldToken);

    return $token;
}
```

### Custom Claims.

Of course, there are support for custom claims.

You can set them in two ways.

#### By explicitly passing them.

```php

$customClaims = [
    'custom1' => 'value1',
    'custom2' => 'value2',
];

// when issuing
$auth->issue($customClaims);

// when refreshing
// custom claims are the second parameter as the first one is the
// old token
$auth->refresh(null, $customClaims);

```

#### By Authenticatable method.

If all your users will have the same custom claims, you can setup a default
custom claims method on your User's model (or any other Authenticatable you're using):

If the method `customJWTClaims()` is present on the model being issue the token against,
this claims will be automatically included.

```php

class User extends Model implements Authenticatable
{
    public function customJWTClaims()
    {
        return [
            'email' => $this->email,
            'name'  => $this->name,
        ];
    }
}




```
