<?php
namespace OCA\oc_user_pwd;

require_once('pwd_sha.php');

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
        if (!PasswordSHA::check($password, $user['password']))
            return false;
        return $user['uid'];
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

	// --------------------------------------------------------
	// IUserManager methods
	// --------------------------------------------------------
	public function getBackends() {
		\OCP\Util::writeLog('oc_user_pwd', 'getBackends(): Method not implemented', \OCP\Util::WARN);
		return false;
	}

	public function getUsers($search = '', $limit = 10, $offset = 0) {
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
