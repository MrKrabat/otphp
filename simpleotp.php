<?php
/*
 * Copyright (c) 2018 MrKrabat
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

class SimpleOTP {
    private static $BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private $secret;
    private $tokenTime;
    private $tokenLength;
    private $tokenCounter;
    private $tokenAlgo;

    /**
     * Creates SimpleOTP instance
     * @param $secret - secret in base32 or binary format
     * @param $isSecretBase32 - true if secret is in base32 format
     * @param $tokenTime - how long in seconds a token is valid
     * @param $tokenLength - length of token
     * @param $tokenCounter - token counter (only for HOTP)
     * @param $tokenAlgo - Hash algorithm to use, see https://secure.php.net/manual/en/function.hash-hmac-algos.php
     **/
    function __construct($secret, $isSecretBase32 = true, $tokenTime = 30, $tokenLength = 6, $tokenCounter = 0, $tokenAlgo = "sha1") {
        $this->tokenTime = $tokenTime;
        $this->tokenLength = $tokenLength;
        $this->tokenCounter = $tokenCounter;
        $this->tokenAlgo = $tokenAlgo;

        if ($isSecretBase32) {
            // decode base32 to binary
            $this->secret = self::base32_decode($secret);
        } else {
            $this->secret = $secret;
        }
    }

    /**
     * Generates OTP token
     * @param $otpMode - true for TOTP, false for HOTP
     * @param $tokenInfo - timestamp or counter value to use
     * @return string
     **/
    public function getToken($otpMode = true, $tokenInfo = Null) {
        if ($tokenInfo !== Null && !$otpMode) {
            $hmac_counter = pack("N*", 0) . pack("N*", $tokenInfo);
        } elseif ($tokenInfo !== Null && $otpMode) {
            $hmac_counter = pack("N*", 0) . pack("N*", $this->getTimecode($tokenInfo));
        } elseif ($otpMode) {
            $hmac_counter = pack("N*", 0) . pack("N*", $this->getTimecode());
        } else {
            $hmac_counter = pack("N*", 0) . pack("N*", $this->getTokenCounter());
            $this->tokenCounter++;
        }

        $hash = hash_hmac($this->getTokenAlgorithm(), $hmac_counter, $this->secret, true);
        return str_pad($this->generateOTP($hash), $this->getTokenLength(), "0", STR_PAD_LEFT);
    }

    /**
     * Verifys a user inputted key against the current timestamp. Checks $window
     * keys either side of the timestamp.
     *
     * @param string $b32seed
     * @param string $key - User specified key
     * @param integer $window
     * @param boolean $useTimeStamp
     * @return boolean
     **/
    public function verify($token, $tokenTime = Null, $tokenWindow = 0) {
        if ($tokenTime === Null) {
            $tokenTime = $this->getTimecode();
        }
    }

    /**
     * generateOTP
     * @param $hash
     * @return integer
     **/
    private function generateOTP($hash) {
        $offset = ord($hash[strlen($hash)-1]) & 0xf;

        return (((ord($hash[$offset]) & 0x7f) << 24 ) |
            ((ord($hash[$offset+1]) & 0xff) << 16 ) |
            ((ord($hash[$offset+2]) & 0xff) << 8 ) |
            (ord($hash[$offset+3]) & 0xff)
        ) % pow(10, $this->getTokenLength());
    }

    /**
     * Returns the current Unix Timestamp devided by tokenTime
     * @param $timecode - Unix Timestamp
     * @return integer
     **/
    public function getTimecode($timecode = Null) {
        if ($timecode === Null) {
            $timecode = microtime(true);
        }
        return floor($timecode/$this->getTokenTime());
    }

    /**
     * Returns token counter
     * @return integer
     **/
    public function getTokenCounter() {
        return $this->tokenCounter;
    }

    /**
     * Sets token counter
     * @param $tokenCounter - token counter (only for HOTP)
     **/
    public function setTokenCounter($tokenCounter) {
        $this->tokenCounter = $tokenCounter;
    }

    /**
     * Returns token length
     * @return integer
     **/
    public function getTokenLength() {
        return $this->tokenLength;
    }

    /**
     * Sets token length
     * @param $tokenLength - length of token
     **/
    public function setTokenLength($tokenLength) {
        $this->tokenLength = $tokenLength;
    }

    /**
     * Returns token time
     * @return integer
     **/
    public function getTokenTime() {
        return $this->tokenTime;
    }

    /**
     * Sets token time
     * @param $tokenTime - how long in seconds a token is valid
     **/
    public function setTokenTime($tokenTime) {
        $this->tokenTime = $tokenTime;
    }

    /**
     * Returns token algorithm
     * @return string
     **/
    public function getTokenAlgorithm() {
        return $this->tokenAlgo;
    }

    /**
     * Sets token algorithm
     * @param $tokenAlgo - Hash algorithm to use, see https://secure.php.net/manual/en/function.hash-hmac-algos.php
     **/
    public function setTokenAlgorithm($tokenAlgo) {
        $this->tokenAlgo = $tokenAlgo;
    }

    /**
     * Generates a secret key in base32 format
     * @param $secretLength - length of base32 secret, must be a multiple of 8
     * @param $secretBase32 - true to return base32, false for binary
     * @return string
     **/
    public static function generateSecretKey($secretLength = 16, $secretBase32 = true) {
        $ret = "";

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
    public static function base32_decode($input) {
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
?>