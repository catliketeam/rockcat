<?php

namespace App\Services\Auth;

use App\User;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Log;

class TwitterAuthService
{
    protected $clientId;
    protected $clientSecret;
    protected $redirectUri;
    protected $apiVersion = '2';

    public function __construct()
    {
        $this->clientId = config('services.twitter.client_id');
        $this->clientSecret = config('services.twitter.client_secret');
        $this->redirectUri = url('/auth/twitter/callback');
        
        Log::info('TwitterAuthService initialized', [
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri
        ]);
    }

    public function getAuthUrl()
    {
        $state = Str::random(40);
        session()->put('twitter_state', $state);

        $params = [
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'state' => $state,
            'scope' => 'tweet.read users.read offline.access',
            'response_type' => 'code',
            'code_challenge' => $this->generateCodeChallenge(),
            'code_challenge_method' => 'S256',
        ];

        $url = 'https://twitter.com/i/oauth2/authorize?' . http_build_query($params);
        Log::info('Generated Twitter auth URL', ['url' => $url]);
        
        return $url;
    }

    protected function generateCodeChallenge()
    {
        $verifier = Str::random(128);
        session()->put('twitter_code_verifier', $verifier);
        return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    }

    public function getAccessToken($code)
    {
        Log::info('Requesting access token from Twitter', ['code' => $code]);
        
        $response = Http::withBasicAuth($this->clientId, $this->clientSecret)
            ->asForm()
            ->post('https://api.twitter.com/2/oauth2/token', [
                'code' => $code,
                'grant_type' => 'authorization_code',
                'redirect_uri' => $this->redirectUri,
                'code_verifier' => session('twitter_code_verifier'),
            ]);

        $data = $response->json();
        Log::info('Twitter access token response', ['response' => $data]);

        if ($response->failed()) {
            Log::error('Failed to get access token', [
                'status' => $response->status(),
                'body' => $data
            ]);
            throw new \Exception('Failed to get access token: ' . ($data['error_description'] ?? 'Unknown error'));
        }

        if (!isset($data['access_token'])) {
            Log::error('No access token in response', ['response' => $data]);
            throw new \Exception('No access token in response');
        }

        return $data;
    }

    public function getUserInfo($accessToken)
    {
        Log::info('Requesting user info from Twitter', ['token' => substr($accessToken, 0, 10) . '...']);
        
        $response = Http::withToken($accessToken)
            ->get('https://api.twitter.com/2/users/me', [
                'user.fields' => 'id,name,username,profile_image_url,confirmed_email',
            ]);

        $data = $response->json();
        Log::info('Twitter user info response', ['response' => $data]);

        if ($response->failed()) {
            Log::error('Failed to get user info', [
                'status' => $response->status(),
                'body' => $data
            ]);
            throw new \Exception('Failed to get user info: ' . ($data['detail'] ?? 'Unknown error'));
        }

        if (!isset($data['data']['id'])) {
            Log::error('No user ID in response', ['response' => $data]);
            throw new \Exception('No user ID in response');
        }

        return $data['data'];
    }

    public function handleCallback($code)
    {
        Log::info('Twitter callback started', ['code' => $code]);

        try {
            $tokenData = $this->getAccessToken($code);
            if (!isset($tokenData['access_token'])) {
                Log::error('Failed to get access token from Twitter', ['response' => $tokenData]);
                throw new \Exception('Failed to get access token from Twitter');
            }

            $userInfo = $this->getUserInfo($tokenData['access_token']);
            Log::info('Got user info from Twitter', ['userInfo' => $userInfo]);
            
            // Check for existing user including soft-deleted ones
            $user = User::withTrashed()->where('twitter_id', $userInfo['id'])->first();
            
            if (!$user) {
                Log::info('Creating new user from Twitter data', ['userInfo' => $userInfo]);
                $user = User::create([
                    'name' => $userInfo['name'],
                    'email' => $userInfo['email'] ?? null,
                    'username' => $this->generateUniqueUsername($userInfo['username']),
                    'password' => bcrypt(Str::random(32)),
                    'twitter_id' => $userInfo['id'],
                    'twitter_token' => $tokenData['access_token'],
                    'twitter_token_secret' => $tokenData['refresh_token'] ?? null,
                    'twitter_token_expires_at' => now()->addSeconds($tokenData['expires_in'] ?? 0),
                    'email_verified_at' => now(),
                    'register_source' => 'twitter',
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
                    'twitter_token' => $tokenData['access_token'],
                    'twitter_token_secret' => $tokenData['refresh_token'] ?? null,
                    'twitter_token_expires_at' => now()->addSeconds($tokenData['expires_in'] ?? 0),
                ]);
                Log::info('Updated existing user', ['user_id' => $user->id]);
            }

            Log::info('Attempting to login user', ['user_id' => $user->id]);
            Auth::login($user);
            Log::info('User logged in successfully', ['user_id' => $user->id]);

            return $user;
        } catch (\Exception $e) {
            Log::error('Error in Twitter callback', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            throw $e;
        }
    }

    protected function generateUniqueUsername($username)
    {
        $baseUsername = Str::slug($username);
        $username = $baseUsername;
        $counter = 1;

        while (User::where('username', $username)->exists()) {
            $username = $baseUsername . $counter;
            $counter++;
        }

        return $username;
    }
} 