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
        
        Log::info('FacebookAuthService initialized', [
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri
        ]);
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

        $url = 'https://www.facebook.com/' . $this->graphVersion . '/dialog/oauth?' . http_build_query($params);
        Log::info('Generated Facebook auth URL', ['url' => $url]);
        
        return $url;
    }

    public function getAccessToken($code)
    {
        Log::info('Requesting access token from Facebook', ['code' => $code]);
        
        $response = Http::get('https://graph.facebook.com/' . $this->graphVersion . '/oauth/access_token', [
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'redirect_uri' => $this->redirectUri,
            'code' => $code,
        ]);

        $data = $response->json();
        Log::info('Facebook access token response', ['response' => $data]);

        if ($response->failed()) {
            Log::error('Failed to get access token', [
                'status' => $response->status(),
                'body' => $data
            ]);
            throw new \Exception('Failed to get access token: ' . ($data['error']['message'] ?? 'Unknown error'));
        }

        if (!isset($data['access_token'])) {
            Log::error('No access token in response', ['response' => $data]);
            throw new \Exception('No access token in response');
        }

        return $data;
    }

    public function getUserInfo($accessToken)
    {
        Log::info('Requesting user info from Facebook', ['token' => substr($accessToken, 0, 10) . '...']);
        
        $response = Http::get('https://graph.facebook.com/' . $this->graphVersion . '/me', [
            'fields' => 'id,name,email,picture',
            'access_token' => $accessToken,
        ]);

        $data = $response->json();
        Log::info('Facebook user info response', ['response' => $data]);

        if ($response->failed()) {
            Log::error('Failed to get user info', [
                'status' => $response->status(),
                'body' => $data
            ]);
            throw new \Exception('Failed to get user info: ' . ($data['error']['message'] ?? 'Unknown error'));
        }

        if (!isset($data['id'])) {
            Log::error('No user ID in response', ['response' => $data]);
            throw new \Exception('No user ID in response');
        }

        return $data;
    }

    public function handleCallback($code)
    {
        Log::info('Facebook callback started', ['code' => $code]);

        try {
        $tokenData = $this->getAccessToken($code);
        $tokenData = $this->getAccessToken($code);
        if (!isset($tokenData['access_token'])) {
            Log::error('Failed to get access token from Facebook', ['response' => $tokenData]);
            throw new \Exception('Failed to get access token from Facebook');
        }

            $tokenData = $this->getAccessToken($code);
        if (!isset($tokenData['access_token'])) {
            Log::error('Failed to get access token from Facebook', ['response' => $tokenData]);
            throw new \Exception('Failed to get access token from Facebook');
        }

        $userInfo = $this->getUserInfo($tokenData['access_token']);
        $userInfo = $this->getUserInfo($tokenData['access_token']);
        Log::info('Got user info from Facebook', ['userInfo' => $userInfo]);
            $userInfo = $this->getUserInfo($tokenData['access_token']);
        Log::info('Got user info from Facebook', ['userInfo' => $userInfo]);
            
            // Check for existing user including soft-deleted ones
            $user = User::withTrashed()->where('facebook_id', $userInfo['id'])->first();
            
            if (!$user) {
                Log::info('Creating new user from Facebook data', ['userInfo' => $userInfo]);
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
                Log::info('New user created', ['user_id' => $user->id]);
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
                Log::info('Updated existing user', ['user_id' => $user->id]);
            }

            Log::info('Attempting to login user', ['user_id' => $user->id]);
            Auth::login($user);
            Log::info('User logged in successfully', ['user_id' => $user->id]);

            return $user;
        } catch (\Exception $e) {
            Log::error('Error in Facebook callback', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
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