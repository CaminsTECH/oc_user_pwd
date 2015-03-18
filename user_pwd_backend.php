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

	public function checkPassword($uid, $password) {
		$user = $this->getUser($uid);
		$hash = $this->getUserHash($user);
		if (!$hash) 
			return false;

		$sha1 = $this->createSHA1($password, $hash['salt']);
		if (!$this->hashEquals($hash['sha1'], $sha1))
			return false;

		return $user['uid'];
	}

	private function getUserHash($user) {
		$password = base64_decode($user['password']);
		if (substr($password, 0, 6) != '{SSHA}')
			return false;
	
		$ssha = base64_decode(substr($password, 6));
		$salt = substr($ssha, 20);
		$sha1 = substr($ssha, 0, 20);
		return array('sha1' => $sha1, 'salt' => $salt); 
	}

	private function getUser($uid) {
		$query = $this->db->prepare('SELECT uid, password FROM oc_users WHERE LOWER(uid) = LOWER(?)');
		$result = $query->execute(array($uid));
		if (!$result)
			return false;
		$user = $query->fetch();
		if (!$user)
			return false;
		return $user;
	}

	private function createSHA1($text, $salt) {
		return pack("H*", sha1($text.$salt));
	}

	private function hashEquals($known, $user) {
		if (function_exists('hash_equals'))
			return (hash_equals($known, $user));
		return $known == $user;
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
		return (bool)((OC_USER_BACKEND_CHECK_PASSWORD) & $actions);
	}

	public function hasUserListings() {
		return false;
	}
}
