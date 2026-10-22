#!/bin/sh
# Wrapper so php2shell_check.py can probe a PHP inside Docker: IMAGE=php:8.3-cli demo/dphp.sh -r '...'
exec docker run --rm "${IMAGE:-php:8.3-cli}" php ${PHP_ARGS} "$@"
