<?php

namespace OCA\oc_user_pwd;

class PasswordSHA {
    public static function check($text, $sha) {
        if (substr($sha, 0, 5) == '{SHA}')
            return self::checkSHA($text, substr($sha, strlen('{SHA}')));

        if (substr($sha, 0, 6) == '{SSHA}')
            return self::checkSSHA($text, substr($sha, strlen('{SSHA}')));

        return false;
    }

    private static function checkSHA($text, $sha) {
        $sha = base64_decode($sha);
        return self::hashEquals(self::createHashSHA($text), $sha);
    }

    private static function checkSSHA($text, $sha) {
        $sha = base64_decode($sha);
        $shaHash = substr($sha, 0, 20);
        $shaSalt = substr($sha, 20);
        return self::hashEquals(self::createHashSHA($text, $shaSalt), $shaHash);
    }

    private static function createHashSHA($text, $salt = '') {
        return pack("H*", sha1($text.$salt));
    }

    private static function hashEquals($known, $user) {
        if (function_exists('hash_equals'))
            return (hash_equals($known, $user));
        return $known == $user;
    }
}
