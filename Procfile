web: vendor/bin/heroku-php-apache2 -i custom_php.ini public/
worker: php artisan queue:work --tries=3 --timeout=300


