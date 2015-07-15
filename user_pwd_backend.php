<?php

namespace OCA\oc_user_pwd;

class USER_PWD_BACKEND implements \OCP\IUserManager, \OCP\UserInterface  {

	protected $db;

	public function __construct($db) {
		$this->db = $db;
	}

	// --------------------------------------------------------
	// IUserManager methods
	// --------------------------------------------------------
	public function registerBackend($backend) {
		\OCP\Util::writeLog('oc_user_pwd', 'registerBackend('.get_class($backend).'): Method not implemented', \OCP\Util::WARN);
	}

	public function removeBackend($backend) {
		\OCP\Util::writeLog('oc_user_pwd', 'removeBackend('.get_class($backend).'): Method not implemented', \OCP\Util::WARN);
	}

	public function clearBackends() {
		\OCP\Util::writeLog('oc_user_pwd', 'clearBackends(): Method not implemented', \OCP\Util::WARN);
	}

	public function get($uid) { 
		\OCP\Util::writeLog('oc_user_pwd', 'get('.$uid.'): Method not implemented', \OCP\Util::WARN);
		return null; 
	}

	public function userExists($uid) {
		if (!empty($uid))
			\OCP\Util::writeLog('oc_user_pwd', 'userExists('.$uid.'): Method not implemented', \OCP\Util::WARN);
		return false; 
	}

	public function search($pattern, $limit = null, $offset = null) { 
		\OCP\Util::writeLog('oc_user_pwd', 'search('.$pattern.'): Method not implemented', \OCP\Util::WARN);
		return array(); 
	}

	public function searchDisplayName($pattern, $limit = null, $offset = null) { 
		\OCP\Util::writeLog('oc_user_pwd', 'searchDisplayName('.$pattern.'): Method not implemented', \OCP\Util::WARN);
		return array(); 
	}

	public function createUser($uid, $password) { 
		\OCP\Util::writeLog('oc_user_pwd', 'createUser('.$uid.'): Method not implemented', \OCP\Util::WARN);
		return false; 
	}

	public function countUsers() { 
		\OCP\Util::writeLog('oc_user_pwd', 'countUsers(): Method not implemented', \OCP\Util::WARN);
		return 0; 
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
		$query = $this->db->prepare('SELECT uid, password FROM `*PREFIX*users` WHERE LOWER(uid) = LOWER(?)');
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

	// --------------------------------------------------------
	// IUserManager methods
	// --------------------------------------------------------
	public function getUsers($search = '', $limit = 10, $offset = 0) { 
		\OCP\Util::writeLog('oc_user_pwd', 'getUsers('.$search.'): Method not implemented', \OCP\Util::WARN);
		return array(); 
	}

	public function deleteUser($uid) { 
		\OCP\Util::writeLog('oc_user_pwd', 'deleteUser('.$uid.'): Method not implemented', \OCP\Util::WARN);
		return false; 
	}

	public function getDisplayName($uid) { 
		\OCP\Util::writeLog('oc_user_pwd', 'getDisplayName('.$uid.'): Method not implemented', \OCP\Util::WARN);
		return false; 
	}

	public function getDisplayNames($search = '', $limit = null, $offset = null) { 
		\OCP\Util::writeLog('oc_user_pwd', 'getDisplayNames('.$search.'): Method not implemented', \OCP\Util::WARN);
		return array(); 
	}

	public function hasUserListings() { 
		\OCP\Util::writeLog('oc_user_pwd', 'hasUserListings(): Method not implemented', \OCP\Util::WARN);
		return false; 
	}

	public function implementsActions($actions) {
		return (bool)((OC_USER_BACKEND_CHECK_PASSWORD) & $actions);
	}
}
