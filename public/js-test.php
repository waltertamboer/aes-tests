<?php

use Zend\Crypt\BlockCipher;

require __DIR__ . '/../vendor/autoload.php';

function createBlockCipher($password)
{
    $blockCipher = BlockCipher::factory('openssl', [
        'algo' => 'aes',
        'mode' => 'cbc',
        'padding' => 'pkcs7',
    ]);

    $blockCipher->setKey($password);

    if (!empty($_GET['ajax_salt'])) {
        $blockCipher->setSalt($_GET['ajax_salt']);
    }
    $blockCipher->setKeyIteration(5000);

    return $blockCipher;
}


if (isset($_GET['ajax_encrypt'])) {
    echo json_encode(createBlockCipher($_GET['ajax_password'])->encrypt($_GET['ajax_encrypt']), JSON_PRETTY_PRINT);
    exit;
}

if (isset($_GET['ajax_decrypt'])) {
    echo json_encode(createBlockCipher($_GET['ajax_password'])->decrypt($_GET['ajax_decrypt']), JSON_PRETTY_PRINT);
    exit;
}

?>
<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <title>AES Test</title>
        <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.1.1/jquery.min.js"></script>
        <script type="text/javascript" src="../bower_components/crypto-js/crypto-js.js"></script>
        <script type="text/javascript" src="js/js-test.js"></script>
    </head>
    <body>

        <p>
            See the console for the result.
        </p>

    </body>
</html>


