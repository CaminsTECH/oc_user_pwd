<?php

$db = \OC::$server->getDatabaseConnection();
$backend  = new OCA\oc_user_pwd\USER_PWD_BACKEND($db);
OC_User::useBackend($backend);
