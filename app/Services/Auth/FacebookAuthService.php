<?php

namespace App\Services\Auth;

use App\User;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Log;

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
        Log::info('Facebook callback started', ['code' => $code]);

        $tokenData = $this->getAccessToken($code);
        if (!isset($tokenData['access_token'])) {
            Log::error('Failed to get access token from Facebook', ['response' => $tokenData]);
            throw new \Exception('Failed to get access token from Facebook');
        }

        $userInfo = $this->getUserInfo($tokenData['access_token']);
        Log::info('Got user info from Facebook', ['userInfo' => $userInfo]);
        
        // Check for existing user including soft-deleted ones
        $user = User::withTrashed()->where('facebook_id', $userInfo['id'])->first();
        
        if (!$user) {
            Log::info('Creating new user from Facebook data');
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
            Log::info('Found existing user', ['user_id' => $user->id]);
            
            // If user was soft-deleted, restore them
            if ($user->trashed()) {
                Log::info('Restoring soft-deleted user', ['user_id' => $user->id]);
                $user->restore();
            }
            
            $user->update([
                'facebook_token' => $tokenData['access_token'],
                'facebook_token_expires_at' => now()->addSeconds($tokenData['expires_in'] ?? 0),
            ]);
        }

        Log::info('Attempting to login user', ['user_id' => $user->id]);
        Auth::login($user);
        Log::info('User logged in successfully', ['user_id' => $user->id]);

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