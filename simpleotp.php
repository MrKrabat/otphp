<?php
/*
 * Copyright (c) 2018 MrKrabat
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

interface iSimpleOTP {
    public function getToken(int $tokenInfo = Null): string;
    public function verify(string $token, int $tokenWindow = 0, int $tokenInfo = Null): bool;
}

class SimpleOTP {
    private static $BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    protected $secret;
    private $tokenTime;
    private $tokenLength;
    private $tokenAlgo;

    /**
     * Creates SimpleOTP instance
     * @param $secret - secret in base32 or binary format
     * @param $isSecretBase32 - true if secret is in base32 format
     * @param $tokenTime - how long in seconds a token is valid
     * @param $tokenLength - length of token
     * @param $tokenAlgo - Hash algorithm to use, see https://secure.php.net/manual/en/function.hash-hmac-algos.php
     **/
    function __construct(string $secret, bool $isSecretBase32 = true, int $tokenTime = 30, int $tokenLength = 6, string $tokenAlgo = "sha1") {
        $this->tokenTime = $tokenTime;
        $this->tokenLength = $tokenLength;
        $this->tokenAlgo = $tokenAlgo;

        if ($isSecretBase32) {
            // decode base32 to binary
            $this->secret = self::base32_decode($secret);
        } else {
            $this->secret = $secret;
        }
    }

    /**
     * generateOTP
     * @param $hash
     * @return integer
     **/
    protected function generateOTP(string $hash): int {
        $offset = ord($hash[strlen($hash)-1]) & 0xf;

        return (((ord($hash[$offset]) & 0x7f) << 24 ) |
            ((ord($hash[$offset+1]) & 0xff) << 16 ) |
            ((ord($hash[$offset+2]) & 0xff) << 8 ) |
            (ord($hash[$offset+3]) & 0xff)
        ) % pow(10, $this->getTokenLength());
    }

    /**
     * Returns token length
     * @return integer
     **/
    public function getTokenLength(): int {
        return $this->tokenLength;
    }

    /**
     * Sets token length
     * @param $tokenLength - length of token
     **/
    public function setTokenLength(int $tokenLength) {
        $this->tokenLength = $tokenLength;
    }

    /**
     * Returns token time
     * @return integer
     **/
    public function getTokenTime(): int {
        return $this->tokenTime;
    }

    /**
     * Sets token time
     * @param $tokenTime - how long in seconds a token is valid
     **/
    public function setTokenTime(int $tokenTime) {
        $this->tokenTime = $tokenTime;
    }

    /**
     * Returns token algorithm
     * @return string
     **/
    public function getTokenAlgorithm(): string {
        return $this->tokenAlgo;
    }

    /**
     * Sets token algorithm
     * @param $tokenAlgo - Hash algorithm to use, see https://secure.php.net/manual/en/function.hash-hmac-algos.php
     **/
    public function setTokenAlgorithm(string $tokenAlgo) {
        $this->tokenAlgo = $tokenAlgo;
    }

    /**
     * Generates a secret key in base32 format
     * @param $secretLength - length of base32 secret, must be a multiple of 8
     * @param $secretBase32 - true to return base32, false for binary
     * @return string
     **/
    public static function generateSecretKey(int $secretLength = 16, bool $secretBase32 = true): string {
        $ret = "";

        if ($secretLength % 8 !== 0) {
            throw new Exception("secretLength has to be a multiple of 8");
        }

        for ($i = 0; $i < $secretLength; $i++) {
            $ret .= substr(self::$BASE32, random_int(0,31), 1);
        }

        if ($secretBase32) {
            return $ret;
        } else {
            return self::base32_decode($ret);
        }
    }

    /**
     * Decodes base32 as binary string
     * @param $input - base32 string
     * @return string
     **/
    public static function base32_decode(string $input): string {
        $ret = "";

        foreach (str_split(strtoupper($input)) as $b32char) {
            if (false === ($char = strpos(self::$BASE32, $b32char))) {
                $char = 0;
            }
            $ret .= sprintf("%05b", $char);
        }
        $args = array_map("bindec", str_split($ret, 8));
        array_unshift($args, "C*");

        return rtrim(call_user_func_array("pack", $args), "\0");
    }
}

class SimpleTOTP extends SimpleOTP implements iSimpleOTP {
    /**
     * Creates SimpleTOTP instance
     * @param $secret - secret in base32 or binary format
     * @param $isSecretBase32 - true if secret is in base32 format
     * @param $tokenTime - how long in seconds a token is valid
     * @param $tokenLength - length of token
     * @param $tokenAlgo - Hash algorithm to use, see https://secure.php.net/manual/en/function.hash-hmac-algos.php
     **/
    function __construct(string $secret, bool $isSecretBase32 = true, int $tokenTime = 30, int $tokenLength = 6, string $tokenAlgo = "sha1") {
        parent::__construct($secret, $isSecretBase32, $tokenTime, $tokenLength, $tokenAlgo);
    }

    /**
     * Generates TOTP token
     * @param $timecode - timestamp to use
     * @param $isTimecodeNormalized - true if $timecode is from getTimecode()
     * @return string
     **/
    public function getToken(int $timecode = Null, bool $isTimecodeNormalized = true): string {
        if ($timecode !== Null) {
            if ($isTimecodeNormalized) {
                $hmac_counter = pack("N*", 0) . pack("N*", $timecode);
            } else {
                $hmac_counter = pack("N*", 0) . pack("N*", $this->getTimecode($timecode));
            }
        } else {
            $hmac_counter = pack("N*", 0) . pack("N*", $this->getTimecode());
        }

        $hash = hash_hmac($this->getTokenAlgorithm(), $hmac_counter, $this->secret, true);
        return str_pad($this->generateOTP($hash), $this->getTokenLength(), "0", STR_PAD_LEFT);
    }

    /**
     * Verify token from user
     * @param $token - Unsafe user token to compare
     * @param $tokenWindow - How many tokens before/after current counter/time should be compared
     * @param $timecode - timestamp to use
     * @param $isTimecodeNormalized - true if $timecode is from getTimecode()
     * @return boolean
     **/
    public function verify(string $token, int $tokenWindow = 0, int $timecode = Null, bool $isTimecodeNormalized = true): bool {
        if ($timecode !== Null) {
            if (!$isTimecodeNormalized) {
                $timecode = $this->getTimecode($timecode);
            }
        } else {
            $timecode = $this->getTimecode();
        }

        for ($i = $timecode - $tokenWindow; $i <= $timecode + $tokenWindow; $i++) {
            if ($this->getToken($i, true) === $token) {
                return true;
            }
        }

        return false;
    }

    /**
     * Returns the current Unix Timestamp devided by tokenTime
     * @param $timecode - Unix Timestamp with microseconds
     * @return integer
     **/
    public function getTimecode(int $timecode = Null): int {
        if ($timecode === Null) {
            $timecode = microtime(true);
        }
        return floor($timecode/$this->getTokenTime());
    }
}

class SimpleHOTP extends SimpleOTP implements iSimpleOTP {
    private $tokenCounter;

    /**
     * Creates SimpleHOTP instance
     * @param $secret - secret in base32 or binary format
     * @param $isSecretBase32 - true if secret is in base32 format
     * @param $tokenCounter - token counter
     * @param $tokenTime - how long in seconds a token is valid
     * @param $tokenLength - length of token
     * @param $tokenAlgo - Hash algorithm to use, see https://secure.php.net/manual/en/function.hash-hmac-algos.php
     **/
    function __construct(string $secret, bool $isSecretBase32 = true, int $tokenCounter = 0, int $tokenTime = 30, int $tokenLength = 6, string $tokenAlgo = "sha1") {
        parent::__construct($secret, $isSecretBase32, $tokenTime, $tokenLength, $tokenAlgo);
        $this->tokenCounter = $tokenCounter;
    }

    /**
     * Generates HOTP token
     * @param $tokenCounter - counter to use
     * @return string
     **/
    public function getToken(int $tokenCounter = Null): string {
        if ($tokenCounter !== Null) {
            $hmac_counter = pack("N*", 0) . pack("N*", $tokenCounter);
        } else {
            $hmac_counter = pack("N*", 0) . pack("N*", $this->getTokenCounter());
            $this->tokenCounter++;
        }

        $hash = hash_hmac($this->getTokenAlgorithm(), $hmac_counter, $this->secret, true);
        return str_pad($this->generateOTP($hash), $this->getTokenLength(), "0", STR_PAD_LEFT);
    }

    /**
     * Verify token from user
     * @param $token - Unsafe user token to compare
     * @param $tokenWindow - How many tokens before/after current counter should be compared
     * @param $tokenCounter - counter value to use
     * @return boolean
     **/
    public function verify(string $token, int $tokenWindow = 0, int $tokenCounter = Null): bool {
        if ($tokenCounter === Null) {
            $tokenCounter = $this->getTokenCounter();
            $this->tokenCounter++;
        }

        for ($i = $tokenCounter - $tokenWindow; $i <= $tokenCounter + $tokenWindow; $i++) {
            if ($this->getToken($i, true) === $token) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns token counter
     * @return integer
     **/
    public function getTokenCounter(): int {
        return $this->tokenCounter;
    }

    /**
     * Sets token counter
     * @param $tokenCounter - token counter
     **/
    public function setTokenCounter(int $tokenCounter) {
        $this->tokenCounter = $tokenCounter;
    }
}
?>