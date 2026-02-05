# 1. Use PHP 8.2 FPM as the base image
FROM php:8.2-fpm

# 2. Install system dependencies
# We need Nginx (web server), Supervisor (process manager),
# Node.js (for frontend build), and PostgreSQL drivers.
RUN apt-get update && apt-get install -y \
    git \
    curl \
    libpng-dev \
    libonig-dev \
    libxml2-dev \
    zip \
    unzip \
    libpq-dev \
    nginx \
    supervisor \
    && docker-php-ext-install pdo_pgsql mbstring exif pcntl bcmath gd

# 3. Install Node.js (Version 20) and NPM
# This is required to run 'npm run build' for your React frontend
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs

# 4. Install Composer (PHP Package Manager)
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

# 5. Set working directory
WORKDIR /var/www/html

# 6. Copy existing application directory contents
COPY . .

# 7. Create a custom Nginx configuration file
# This tells Nginx to serve the Laravel 'public' folder
RUN echo "server { \
    listen 8000; \
    root /var/www/html/public; \
    add_header X-Frame-Options \"SAMEORIGIN\"; \
    add_header X-Content-Type-Options \"nosniff\"; \
    index index.php; \
    charset utf-8; \
    location / { \
        try_files \$uri \$uri/ /index.php?\$query_string; \
    } \
    location = /favicon.ico { access_log off; log_not_found off; } \
    location = /robots.txt  { access_log off; log_not_found off; } \
    error_page 404 /index.php; \
    location ~ \.php$ { \
        fastcgi_pass 127.0.0.1:9000; \
        fastcgi_param SCRIPT_FILENAME \$realpath_root\$fastcgi_script_name; \
        include fastcgi_params; \
    } \
    location ~ /\.(?!well-known).* { \
        deny all; \
    } \
}" > /etc/nginx/sites-available/default

# 8. Configure Supervisor
# This runs Nginx and PHP-FPM at the same time
RUN echo "[supervisord] \n\
nodaemon=true \n\
[program:nginx] \n\
command=nginx -g 'daemon off;' \n\
stdout_logfile=/dev/stdout \n\
stdout_logfile_maxbytes=0 \n\
stderr_logfile=/dev/stderr \n\
stderr_logfile_maxbytes=0 \n\
[program:php-fpm] \n\
command=php-fpm \n\
stdout_logfile=/dev/stdout \n\
stdout_logfile_maxbytes=0 \n\
stderr_logfile=/dev/stderr \n\
stderr_logfile_maxbytes=0" > /etc/supervisor/conf.d/supervisord.conf

# 9. Install PHP Dependencies
RUN composer install --no-dev --optimize-autoloader

# 10. Install Node Dependencies and Build Assets
# This compiles your React/Inertia code into the public folder
RUN npm install && npm run build

# 11. Fix Permissions
RUN chown -R www-data:www-data /var/www/html/storage /var/www/html/bootstrap/cache

# 12. Expose the port (Koyeb looks for 8000 by default with this config)
EXPOSE 8000

# 13. Start Supervisor (Entrypoint)
# We also run migration and cache commands on startup
CMD sh -c "php artisan config:cache && php artisan route:cache && php artisan view:cache && php artisan migrate --force && /usr/bin/supervisord"
