<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Services\Auth\FacebookAuthService;
use Illuminate\Http\Request;

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
        return redirect($this->facebookService->getAuthUrl());
    }

    public function callback(Request $request)
    {
        abort_unless(config('services.facebook.enabled'), 404);

        if ($request->state !== session()->pull('facebook_state')) {
            return redirect('/login')->with('error', 'Invalid state parameter');
        }

        if ($request->has('error')) {
            return redirect('/login')->with('error', $request->error_description);
        }

        try {
            $user = $this->facebookService->handleCallback($request->code);
            return redirect('/i/web');
        } catch (\Exception $e) {
            return redirect('/login')->with('error', 'Failed to authenticate with Facebook');
        }
    }
} 