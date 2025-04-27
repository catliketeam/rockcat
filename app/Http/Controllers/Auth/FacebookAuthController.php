<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Services\Auth\FacebookAuthService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Auth;

class FacebookAuthController extends Controller
{
    protected $facebookService;

    public function __construct(FacebookAuthService $facebookService)
    {
        $this->facebookService = $facebookService;
    }

    public function redirect()
    {
        abort_unless(config('services.facebook.enabled'), 404);
        Log::info('Facebook redirect initiated', [
            'enabled' => config('services.facebook.enabled'),
            'client_id' => config('services.facebook.client_id')
        ]);
        return redirect($this->facebookService->getAuthUrl());
    }

    public function callback(Request $request)
    {
        abort_unless(config('services.facebook.enabled'), 404);

        Log::info('Facebook callback received', [
            'request' => $request->all(),
            'session_id' => session()->getId()
        ]);

        if ($request->state !== session()->pull('facebook_state')) {
            Log::error('Invalid state parameter', [
                'received' => $request->state,
                'expected' => session()->get('facebook_state'),
                'session_id' => session()->getId()
            ]);
            return redirect('/login')->with('error', 'Invalid state parameter');
        }

        if ($request->has('error')) {
            Log::error('Facebook returned error', ['error' => $request->all()]);
            return redirect('/login')->with('error', $request->error_description);
        }

        try {
            Log::info('Processing Facebook callback with code', ['code' => $request->code]);
            $user = $this->facebookService->handleCallback($request->code);
            
            // Give the session a moment to establish
            sleep(1);
            
            // Check if user is properly authenticated
            if (!Auth::check()) {
                Log::error('User not authenticated after Facebook callback', [
                    'user_id' => $user->id ?? null,
                    'session_id' => session()->getId()
                ]);
                return redirect('/login')->with('error', 'Authentication failed');
            }

            Log::info('User successfully authenticated', [
                'user_id' => Auth::id(),
                'session_id' => session()->getId()
            ]);

            // Redirect to the intended URL or default to home
            $redirectTo = session()->pull('url.intended', '/i/web');
            Log::info('Redirecting user after successful login', ['redirect_to' => $redirectTo]);
            
            return redirect($redirectTo);
        } catch (\Exception $e) {
            Log::error('Facebook authentication failed', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
                'session_id' => session()->getId()
            ]);
            return redirect('/login')->with('error', 'Failed to authenticate with Facebook: ' . $e->getMessage());
        }
    }
} 