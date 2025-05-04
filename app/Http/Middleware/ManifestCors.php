<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class ManifestCors
{
    public function handle(Request $request, Closure $next)
    {
        if ($request->is('manifest.json')) {
            $response = $next($request);
            $response->headers->set('Access-Control-Allow-Origin', '*');
            $response->headers->set('Access-Control-Allow-Methods', 'GET');
            $response->headers->set('Access-Control-Allow-Headers', 'Content-Type');
            return $response;
        }

        return $next($request);
    }
} 