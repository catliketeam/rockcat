<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class ModifyFacebookTokenColumns extends Migration
{
    public function up()
    {
        Schema::table('users', function (Blueprint $table) {
            $table->text('facebook_token')->nullable()->change();
            $table->text('facebook_refresh_token')->nullable()->change();
        });
    }

    public function down()
    {
        Schema::table('users', function (Blueprint $table) {
            $table->string('facebook_token')->nullable()->change();
            $table->string('facebook_refresh_token')->nullable()->change();
        });
    }
} 