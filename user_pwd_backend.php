<?php

namespace OCA\oc_user_pwd;

class USER_PWD_BACKEND implements \OCP\UserInterface {
        protected $db;

        public function __construct($db) {
                $this->db = $db;
        }

        public function canChangeAvatar($uid) {
                return false;
        }

        private function hash_equals($known_string, $user_string) {
                if (function_exists('hash_equals'))
                        return (hash_equals($known_string, $user_string));
                return $known_string == $user_string;
        }

        public function checkPassword($uid, $password) {
                $query = $this->db->prepare('SELECT uid, password FROM oc_users WHERE LOWER(uid) = LOWER(?)');
                $result = $query->execute(array($uid));
                if (!$result)
                        return false;

                $row = $query->fetch();
                if (!$row)
                        return false;

                $hash = base64_decode($row['password']);
                if (substr($hash, 0, 6) != '{SSHA}')
                        return false;


                $hash = base64_decode(substr($hash, 6));
                $salt = substr($hash, 20);
                $hash = substr($hash, 0, 20);
                $passwordHash = pack("H*", sha1($password . $salt));

                if (!$this->hash_equals($hash, $passwordHash))
                        return false;

                return $row['uid'];
        }

        public function getUsers($search = '', $limit = 10, $offset = 0) {
                return array();
        }

        public function userExistsOnLDAP($user) {
                return true;
        }

        public function userExists($uid) {
                return true;
        }

        public function deleteUser($uid) {
                return false;
        }

        public function getHome($uid) {
                return false;
        }

        public function getDisplayName($uid) {
                return false;
        }

      public function getDisplayNames($search = '', $limit = null, $offset = null) {
                return array();
        }

        public function implementsActions($actions) {
                return (bool)((OC_USER_BACKEND_CHECK_PASSWORD)
                        & $actions);
        }

        public function hasUserListings() {
                return false;
        }
}

