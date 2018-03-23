<?php
    /*
     * enable error display
     * set in php.ini zend.assertions = 1
     */
    declare(strict_types=1);
    ini_set("display_errors", "On");
    ini_set("error_reporting", "E_ALL");
    error_reporting(E_ALL);
    assert_options(ASSERT_ACTIVE, 1);
    assert_options(ASSERT_WARNING, 0);
    assert_options(ASSERT_QUIET_EVAL, 1);

    /**
     * assert handler
     */
    function assertHandler($file, $line, $code) {
        echo "<b>Test failed</b>: Line '$line'<br>";
    }
    assert_options(ASSERT_CALLBACK, "assertHandler");

    /* import lib */
    require_once("simpleotp.php");

    /* test GoogleAuth HOTP */
    $otp = new SimpleOTP(false, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    assert($otp->getToken(0) === "755224");
    assert($otp->getToken() === "755224");
    assert($otp->getToken(1) === "287082");
    assert($otp->getToken() === "287082");
    assert($otp->getToken(2) === "359152");
    assert($otp->getToken() === "359152");
    assert($otp->getToken(3) === "969429");
    assert($otp->getToken() === "969429");
    assert($otp->getToken(4) === "338314");
    assert($otp->getToken() === "338314");
    assert($otp->getToken(5) === "254676");
    assert($otp->getToken() === "254676");
    assert($otp->getToken(6) === "287922");
    assert($otp->getToken() === "287922");
    assert($otp->getToken(9) === "520489");
    assert($otp->getToken() === "162583");

    /* test verify function */
    assert($otp->verify("520489", 0, 9) === true);
    assert($otp->verify("969429", 0, 3) === true);
    assert($otp->verify("969429", 0, 2) === false);
    assert($otp->verify("969429", 1, 2) === true);

    /* test GoogleAuth TOTP */
    $otp = new SimpleOTP(true, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    assert($otp->getToken(1111111111, false) === "050471");
    assert($otp->getToken(1234567890, false) === "005924");
    assert($otp->getToken(2000000000, false) === "279037");

    /* test verify function */
    assert($otp->verify("050471", 0, 1111111111, false) === true);
    assert($otp->verify("005924", 0, 1234567890, false) === true);
    assert($otp->verify("279037", 0, 2000000030, false) === false);
    assert($otp->verify("279037", 1, 2000000030, false) === true);

    /* test sha256 and 8 digit tan */
    $otp = new SimpleOTP(true, "12345678901234567890123456789012", false, 30, 8, 0, "sha256");
    assert($otp->getToken(1111111109, false) === "68084774");
    assert($otp->getToken(1111111111, false) === "67062674");
    assert($otp->getToken(1234567890, false) === "91819424");

    /* test sha512 and 8 digit tan */
    $otp = new SimpleOTP(true, "1234567890123456789012345678901234567890123456789012345678901234", false, 30, 8, 0, "sha512");
    assert($otp->getToken(59, false) === "90693936");
    assert($otp->getToken(1234567890, false) === "93441116");

    /* generate new secret */
    echo "Test new secret:<br>";
    echo SimpleOTP::generateSecretKey();

    /* assertion test */
    echo "<br><br>Assertion test to see if system works: ";
    assert(false);
?>