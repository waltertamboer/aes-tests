# aes-tests

## Installation

1. Run `composer install`
2. Run `bower install`

## Problem so far

We want encryption via AES CBC HMAC SHA-256. It should be possible to decrypt 
the base64 string created by `Zend\Crypt` and vice versa. When that is possible 
the problem is solved.
