<?php

namespace App\Services\Auth;

use App\Models\User;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

class GoogleAuthService
{
    protected $clientId;
    protected $clientSecret;
    protected $redirectUri;
    protected $scopes;

    public function __construct()
    {
        $this->clientId = config('services.google.client_id');
        $this->clientSecret = config('services.google.client_secret');
        $this->redirectUri = config('services.google.redirect');
        $this->scopes = [
            'openid',
            'profile',
            'email'
        ];
    }

    public function getAuthUrl()
    {
        $state = Str::random(40);
        session(['google_state' => $state]);

        $params = [
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'response_type' => 'code',
            'scope' => implode(' ', $this->scopes),
            'state' => $state,
            'access_type' => 'offline',
            'prompt' => 'consent'
        ];

        return 'https://accounts.google.com/o/oauth2/v2/auth?' . http_build_query($params);
    }

    public function handleCallback($code, $state)
    {
        Log::info('Starting Google callback', ['code' => $code, 'state' => $state]);

        // Verify state
        if ($state !== session('google_state')) {
            Log::error('Invalid state parameter');
            throw new \Exception('Invalid state parameter');
        }

        // Get access token
        $tokenResponse = $this->getAccessToken($code);
        if (!isset($tokenResponse['access_token'])) {
            Log::error('Failed to get access token', ['response' => $tokenResponse]);
            throw new \Exception('Failed to get access token');
        }

        // Get user info
        $userInfo = $this->getUserInfo($tokenResponse['access_token']);
        if (!isset($userInfo['email'])) {
            Log::error('Failed to get user info', ['response' => $userInfo]);
            throw new \Exception('Failed to get user info');
        }

        Log::info('Google user info', ['userInfo' => $userInfo]);

        // Check for existing user by Google ID
        $user = User::where('google_id', $userInfo['sub'])->first();

        if (!$user) {
            // Check for existing user by email
            $user = User::where('email', $userInfo['email'])->first();

            if ($user) {
                // Link Google account to existing user
                $user->update([
                    'google_id' => $userInfo['sub'],
                    'google_token' => $tokenResponse['access_token'],
                    'google_refresh_token' => $tokenResponse['refresh_token'] ?? null,
                    'google_token_expires_at' => now()->addSeconds($tokenResponse['expires_in'] ?? 3600),
                    'registration_source' => 'google'
                ]);
            } else {
                // Create new user
                $user = User::create([
                    'name' => $userInfo['name'],
                    'email' => $userInfo['email'],
                    'password' => Hash::make(Str::random(32)),
                    'google_id' => $userInfo['sub'],
                    'google_token' => $tokenResponse['access_token'],
                    'google_refresh_token' => $tokenResponse['refresh_token'] ?? null,
                    'google_token_expires_at' => now()->addSeconds($tokenResponse['expires_in'] ?? 3600),
                    'registration_source' => 'google'
                ]);
            }
        } else {
            // Update existing Google user's tokens
            $user->update([
                'google_token' => $tokenResponse['access_token'],
                'google_refresh_token' => $tokenResponse['refresh_token'] ?? null,
                'google_token_expires_at' => now()->addSeconds($tokenResponse['expires_in'] ?? 3600)
            ]);
        }

        Auth::login($user);
        return $user;
    }

    protected function getAccessToken($code)
    {
        $response = Http::post('https://oauth2.googleapis.com/token', [
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'code' => $code,
            'redirect_uri' => $this->redirectUri,
            'grant_type' => 'authorization_code'
        ]);

        return $response->json();
    }

    protected function getUserInfo($accessToken)
    {
        $response = Http::withToken($accessToken)
            ->get('https://www.googleapis.com/oauth2/v3/userinfo');

        return $response->json();
    }
} 