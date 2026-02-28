#!/bin/bash

# 1. Run migrations to ensure your jobs table and social_accounts exist
# (The --force flag is required in production environments)
php artisan migrate --force

# 2. Start the queue worker in the background
# The "&" at the end tells the container to run this in the background
php artisan queue:work &

# 3. Start your web server in the foreground
# (Replace this with however you currently start your app, e.g., Apache, Nginx, or Octane)
# This MUST be the last command and must NOT have an "&" at the end.
php artisan serve --host=0.0.0.0 --port=${PORT:-8000}
