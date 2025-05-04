<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Services\Auth\GoogleAuthService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

class GoogleController extends Controller
{
    protected $googleAuthService;

    public function __construct(GoogleAuthService $googleAuthService)
    {
        $this->googleAuthService = $googleAuthService;
    }

    public function redirect()
    {
        return redirect($this->googleAuthService->getAuthUrl());
    }

    public function callback(Request $request)
    {
        try {
            $user = $this->googleAuthService->handleCallback(
                $request->input('code'),
                $request->input('state')
            );

            return redirect()->intended('/');
        } catch (\Exception $e) {
            Log::error('Google authentication failed', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);

            return redirect()->route('login')
                ->with('error', 'Google authentication failed. Please try again.');
        }
    }
} 