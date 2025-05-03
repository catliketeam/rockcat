<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

class CloudflareAccess
{
    /**
     * List of Cloudflare IP ranges
     * Source: https://www.cloudflare.com/ips/
     */
    protected $cloudflareIps = [
        // IPv4
        '173.245.48.0/20',
        '103.21.244.0/22',
        '103.22.200.0/22',
        '103.31.4.0/22',
        '141.101.64.0/18',
        '108.162.192.0/18',
        '190.93.240.0/20',
        '188.114.96.0/20',
        '197.234.240.0/22',
        '198.41.128.0/17',
        '162.158.0.0/15',
        '104.16.0.0/13',
        '104.24.0.0/14',
        '172.64.0.0/13',
        '131.0.72.0/22',
        // IPv6
        '2400:cb00::/32',
        '2606:4700::/32',
        '2803:f800::/32',
        '2405:b500::/32',
        '2405:8100::/32',
        '2a06:98c0::/29',
        '2c0f:f248::/32',
    ];

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next)
    {
        // Only perform checks if IP restriction is enabled
        if (!config('app.restrict_ip_access_cloudflare', false)) {
            return $next($request);
        }

        $clientIp = $request->ip();
        
        // Check if the request is coming from a Cloudflare IP
        if (!$this->isCloudflareIp($clientIp)) {
            Log::warning('Access denied: Request from non-Cloudflare IP', [
                'ip' => $clientIp,
                'user_agent' => $request->userAgent(),
                'url' => $request->fullUrl()
            ]);
            
            return response()->json([
                'error' => 'Access denied. This service is only accessible through Cloudflare.'
            ], 403);
        }

        return $next($request);
    }

    /**
     * Check if an IP address is within Cloudflare's IP ranges
     *
     * @param string $ip
     * @return bool
     */
    protected function isCloudflareIp($ip)
    {
        foreach ($this->cloudflareIps as $range) {
            if ($this->ipInRange($ip, $range)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if an IP is within a CIDR range
     *
     * @param string $ip
     * @param string $range
     * @return bool
     */
    protected function ipInRange($ip, $range)
    {
        if (strpos($range, '/') === false) {
            $range .= '/32';
        }

        list($range, $netmask) = explode('/', $range, 2);
        $rangeDecimal = ip2long($range);
        $ipDecimal = ip2long($ip);
        $wildcardDecimal = pow(2, (32 - $netmask)) - 1;
        $netmaskDecimal = ~ $wildcardDecimal;

        return (($ipDecimal & $netmaskDecimal) == ($rangeDecimal & $netmaskDecimal));
    }
} 