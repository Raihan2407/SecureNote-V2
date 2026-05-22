FROM php:8.2-apache

# Install ekstensi MySQL
RUN docker-php-ext-install mysqli pdo pdo_mysql

# Copy semua file project ke direktori Apache
COPY . /var/www/html/

# Set working directory
WORKDIR /var/www/html

# Aktifkan mod_rewrite
RUN a2enmod rewrite

# Set PORT dari Railway
ENV PORT=80
EXPOSE 80