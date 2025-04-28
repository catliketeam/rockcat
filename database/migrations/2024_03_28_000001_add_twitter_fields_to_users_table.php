<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class AddTwitterFieldsToUsersTable extends Migration
{
    public function up()
    {
        Schema::table('users', function (Blueprint $table) {
            $table->string('twitter_id')->nullable()->unique();
            $table->text('twitter_token')->nullable();
            $table->text('twitter_token_secret')->nullable();
            $table->timestamp('twitter_token_expires_at')->nullable();
        });
    }

    public function down()
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn([
                'twitter_id',
                'twitter_token',
                'twitter_token_secret',
                'twitter_token_expires_at'
            ]);
        });
    }
} 