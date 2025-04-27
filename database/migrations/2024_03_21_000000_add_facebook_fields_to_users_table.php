<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class AddFacebookFieldsToUsersTable extends Migration
{
    public function up()
    {
        Schema::table('users', function (Blueprint $table) {
            $table->string('facebook_id')->nullable()->unique();
            $table->string('facebook_token')->nullable();
            $table->string('facebook_refresh_token')->nullable();
            $table->timestamp('facebook_token_expires_at')->nullable();
        });
    }

    public function down()
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn([
                'facebook_id',
                'facebook_token',
                'facebook_refresh_token',
                'facebook_token_expires_at'
            ]);
        });
    }
} 