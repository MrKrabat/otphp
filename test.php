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
    $otp = new SimpleOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    assert($otp->getToken(false, 0) === "755224");
    assert($otp->getToken(false) === "755224");
    assert($otp->getToken(false, 1) === "287082");
    assert($otp->getToken(false) === "287082");
    assert($otp->getToken(false, 2) === "359152");
    assert($otp->getToken(false) === "359152");
    assert($otp->getToken(false, 3) === "969429");
    assert($otp->getToken(false) === "969429");
    assert($otp->getToken(false, 4) === "338314");
    assert($otp->getToken(false) === "338314");
    assert($otp->getToken(false, 5) === "254676");
    assert($otp->getToken(false) === "254676");
    assert($otp->getToken(false, 6) === "287922");
    assert($otp->getToken(false) === "287922");
    assert($otp->getToken(false, 9) === "520489");
    assert($otp->getToken(false) === "162583");

    /* test GoogleAuth TOTP */
    $otp = new SimpleOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    assert($otp->getToken(true, 1111111111) === "050471");
    assert($otp->getToken(true, 1234567890) === "005924");
    assert($otp->getToken(true, 2000000000) === "279037");

    /* test sha256 and 8 digit tan */
    $otp = new SimpleOTP("12345678901234567890123456789012", false, 30, 8, 0, "sha256");
    assert($otp->getToken(true, 1111111109) === "68084774");
    assert($otp->getToken(true, 1111111111) === "67062674");
    assert($otp->getToken(true, 1234567890) === "91819424");

    /* test sha512 and 8 digit tan */
    $otp = new SimpleOTP("1234567890123456789012345678901234567890123456789012345678901234", false, 30, 8, 0, "sha512");
    assert($otp->getToken(true, 59) === "90693936");
    assert($otp->getToken(true, 1234567890) === "93441116");

    /* generate new secret */
    echo "Test new secret:<br>";
    echo SimpleOTP::generateSecretKey();

    /* assertion test */
    echo "<br><br>Assertion test to see if system works: ";
    assert(false);
?>