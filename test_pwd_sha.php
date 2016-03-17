<?php

namespace OCA\oc_user_pwd;

require_once('pwd_sha.php');

assert_options(ASSERT_ACTIVE, 1);
assert_options(ASSERT_WARNING, 1);
assert_options(ASSERT_QUIET_EVAL, 0);

function test_SSHA() {
    echo("Test ".__FUNCTION__."\n");
    $password = 'PatataBullida';
    $sha = '{SSHA}0aZQBnxh3n9jk2pBvsRQDTEr8QAEz9DL';
    assert(PasswordSHA::check($password, $sha), 'Password SSHA correcte');

    $password = 'PatataBullida2';
    $sha = '{SSHA}0aZQBnxh3n9jk2pBvsRQDTEr8QAEz9DL';
    assert(!PasswordSHA::check($password, $sha), 'Password SSHA incorrecte');
}

function test_SHA() {
    echo("Test ".__FUNCTION__."\n");
    $password = 'PatataBullida';
    $sha = '{SHA}vjJHf12oT+sb3UnnXBugAfpd4Cc=';
    assert(PasswordSHA::check($password, $sha), 'Password SHA correcte');

    $password = 'PatataBullida2';
    $sha = '{SHA}vjJHf12oT+sb3UnnXBugAfpd4Cc=';
    assert(!PasswordSHA::check($password, $sha), 'Password SHA incorrecte');
}

test_SSHA();
test_SHA();
