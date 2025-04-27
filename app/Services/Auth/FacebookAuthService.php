<?php

namespace App\Services\Auth;

use App\User;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;

class FacebookAuthService
{
    protected $clientId;
    protected $clientSecret;
    protected $redirectUri;
    protected $graphVersion = 'v18.0';

    public function __construct()
    {
        $this->clientId = config('services.facebook.client_id');
        $this->clientSecret = config('services.facebook.client_secret');
        $this->redirectUri = url('/auth/facebook/callback');
    }

    public function getAuthUrl()
    {
        $state = Str::random(40);
        session()->put('facebook_state', $state);

        $params = [
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'state' => $state,
            'scope' => 'email,public_profile',
            'response_type' => 'code',
        ];

        return 'https://www.facebook.com/' . $this->graphVersion . '/dialog/oauth?' . http_build_query($params);
    }

    public function getAccessToken($code)
    {
        $response = Http::get('https://graph.facebook.com/' . $this->graphVersion . '/oauth/access_token', [
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'redirect_uri' => $this->redirectUri,
            'code' => $code,
        ]);

        return $response->json();
    }

    public function getUserInfo($accessToken)
    {
        $response = Http::get('https://graph.facebook.com/' . $this->graphVersion . '/me', [
            'fields' => 'id,name,email,picture',
            'access_token' => $accessToken,
        ]);

        return $response->json();
    }

    public function handleCallback($code)
    {
        $tokenData = $this->getAccessToken($code);
        if (!isset($tokenData['access_token'])) {
            throw new \Exception('Failed to get access token from Facebook');
        }

        $userInfo = $this->getUserInfo($tokenData['access_token']);
        
        $user = User::where('facebook_id', $userInfo['id'])->first();
        
        if (!$user) {
            $user = User::create([
                'name' => $userInfo['name'],
                'email' => $userInfo['email'] ?? null,
                'username' => $this->generateUniqueUsername($userInfo['name']),
                'password' => bcrypt(Str::random(32)),
                'facebook_id' => $userInfo['id'],
                'facebook_token' => $tokenData['access_token'],
                'facebook_token_expires_at' => now()->addSeconds($tokenData['expires_in'] ?? 0),
                'email_verified_at' => now(),
                'register_source' => 'facebook',
            ]);
        } else {
            $user->update([
                'facebook_token' => $tokenData['access_token'],
                'facebook_token_expires_at' => now()->addSeconds($tokenData['expires_in'] ?? 0),
            ]);
        }

        Auth::login($user);

        return $user;
    }

    protected function generateUniqueUsername($name)
    {
        $baseUsername = Str::slug($name);
        $username = $baseUsername;
        $counter = 1;

        while (User::where('username', $username)->exists()) {
            $username = $baseUsername . $counter;
            $counter++;
        }

        return $username;
    }
} 