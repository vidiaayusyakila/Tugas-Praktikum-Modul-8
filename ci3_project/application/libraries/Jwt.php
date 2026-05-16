<?php
defined('BASEPATH') OR exit('No direct script access allowed');

/**
 * JWT Library for CodeIgniter 3
 * Simple JWT implementation for token-based authentication
 */
class Jwt {
    
    private $secret_key = 'your_secret_key_change_this_in_production';
    private $algorithm = 'HS256';
    private $expiration = 604800; // 7 days in seconds

    public function __construct()
    {
        $this->secret_key = config_item('jwt_secret_key') ?: $this->secret_key;
        $this->expiration = config_item('jwt_expiration') ?: $this->expiration;
    }

    /**
     * Create JWT token
     * 
     * @param array $payload - Data to encode in token
     * @return string - JWT token
     */
    public function create($payload = array())
    {
        $header = array(
            'typ' => 'JWT',
            'alg' => $this->algorithm
        );

        $payload['iat'] = time();
        $payload['exp'] = time() + $this->expiration;

        $header_encoded = $this->base64_url_encode(json_encode($header));
        $payload_encoded = $this->base64_url_encode(json_encode($payload));

        $signature = hash_hmac(
            'sha256',
            $header_encoded . '.' . $payload_encoded,
            $this->secret_key,
            true
        );
        $signature_encoded = $this->base64_url_encode($signature);

        return $header_encoded . '.' . $payload_encoded . '.' . $signature_encoded;
    }

    /**
     * Verify and decode JWT token
     * 
     * @param string $token - JWT token to verify
     * @return object|false - Decoded payload or false if invalid
     */
    public function verify($token = '')
    {
        if (empty($token)) {
            return false;
        }

        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return false;
        }

        list($header_encoded, $payload_encoded, $signature_encoded) = $parts;

        // Verify signature
        $signature = hash_hmac(
            'sha256',
            $header_encoded . '.' . $payload_encoded,
            $this->secret_key,
            true
        );
        $signature_computed = $this->base64_url_encode($signature);

        if ($signature_computed !== $signature_encoded) {
            return false;
        }

        // Decode payload
        $payload = json_decode($this->base64_url_decode($payload_encoded));

        // Check expiration
        if (isset($payload->exp) && $payload->exp < time()) {
            return false;
        }

        return $payload;
    }

    /**
     * Get token from request header
     * Authorization: Bearer <token>
     * 
     * @return string|false - Token or false if not found
     */
    public function get_token_from_request()
    {
        // Try to get Authorization header
        $auth_header = null;

        // Method 1: Apache/nginx
        if (function_exists('apache_request_headers')) {
            $headers = apache_request_headers();
            $auth_header = isset($headers['Authorization']) ? $headers['Authorization'] : null;
        }

        // Method 2: $_SERVER
        if (!$auth_header && isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $auth_header = $_SERVER['HTTP_AUTHORIZATION'];
        }

        // Method 3: Alternative header name
        if (!$auth_header && isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
            $auth_header = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
        }

        if (!$auth_header) {
            return false;
        }

        // Extract token from "Bearer <token>"
        if (preg_match('/Bearer\s+(\S+)/', $auth_header, $matches)) {
            return $matches[1];
        }

        return false;
    }

    /**
     * Base64 URL encode
     */
    private function base64_url_encode($input)
    {
        return str_replace(
            array('+', '/', '='),
            array('-', '_', ''),
            base64_encode($input)
        );
    }

    /**
     * Base64 URL decode
     */
    private function base64_url_decode($input)
    {
        // Add padding if needed
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $input .= str_repeat('=', 4 - $remainder);
        }

        return base64_decode(
            str_replace(
                array('-', '_'),
                array('+', '/'),
                $input
            )
        );
    }
}
