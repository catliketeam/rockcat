<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Services\Auth\TwitterAuthService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

class TwitterAuthController extends Controller
{
    protected $twitterService;

    public function __construct(TwitterAuthService $twitterService)
    {
        $this->twitterService = $twitterService;
    }

    public function redirect()
    {
        Log::info('Twitter redirect initiated', [
            'enabled' => config('services.twitter.enabled', false),
            'client_id' => config('services.twitter.client_id')
        ]);

        if (!config('services.twitter.enabled', false)) {
            Log::warning('Twitter login is not enabled');
            return redirect()->route('login')->with('error', 'Twitter login is not enabled');
        }

        return redirect($this->twitterService->getAuthUrl());
    }

    public function callback(Request $request)
    {
        Log::info('Twitter callback received', [
            'request' => $request->all(),
            'session_id' => session()->getId()
        ]);

        if ($request->has('error')) {
            Log::error('Twitter authentication error', ['error' => $request->error]);
            return redirect()->route('login')->with('error', 'Twitter authentication failed: ' . $request->error);
        }

        if (!$request->has('code')) {
            Log::error('No code parameter in Twitter callback');
            return redirect()->route('login')->with('error', 'No authorization code received from Twitter');
        }

        if ($request->state !== session('twitter_state')) {
            Log::error('State mismatch in Twitter callback', [
                'request_state' => $request->state,
                'session_state' => session('twitter_state')
            ]);
            return redirect()->route('login')->with('error', 'Invalid state parameter');
        }

        try {
            Log::info('Processing Twitter callback with code', ['code' => $request->code]);
            $user = $this->twitterService->handleCallback($request->code);
            Log::info('User successfully authenticated', [
                'user_id' => $user->id,
                'session_id' => session()->getId()
            ]);
            return redirect()->intended('/');
        } catch (\Exception $e) {
            Log::error('Twitter authentication failed', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            return redirect()->route('login')->with('error', 'Twitter authentication failed: ' . $e->getMessage());
        }
    }
} 