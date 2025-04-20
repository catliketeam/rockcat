#!/usr/bin/env php
<?php

require __DIR__.'/vendor/autoload.php';

$app = require_once __DIR__.'/bootstrap/app.php';
$kernel = $app->make(Illuminate\Contracts\Console\Kernel::class);
$kernel->bootstrap();

use Illuminate\Support\Facades\Storage;

// Upload default avatar to S3
$disk = Storage::disk('s3');
$defaultAvatar = Storage::disk('local')->get('public/avatars/default.jpg');
$disk->put('cache/avatars/default.jpg', $defaultAvatar);

// Update avatar records in database to use the S3 URL
$cdnUrl = $disk->url('cache/avatars/default.jpg');
DB::table('avatars')
    ->where('media_path', 'public/avatars/default.jpg')
    ->update(['cdn_url' => $cdnUrl]);

echo "Default avatar uploaded to S3 and database updated.\n"; 