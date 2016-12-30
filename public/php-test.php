<?php

use Zend\Crypt\BlockCipher;

require __DIR__ . '/../vendor/autoload.php';

function createBlockCipher($password = 'password')
{
    $blockCipher = BlockCipher::factory('openssl', [
        'algo' => 'aes',
        'mode' => 'cbc',
        'padding' => 'pkcs7',
    ]);

    $blockCipher->setKey($password);
    $blockCipher->setKeyIteration(5000);

    return $blockCipher;
}

$encrypted = createBlockCipher()->encrypt('The time is ' . date('H:i:s'));

echo sprintf('<p>Encrypted: %s</p>', $encrypted);
echo sprintf('<p>Encrypted length: %s</p>', strlen($encrypted));
echo sprintf('<p>Decrypted: %s</p>', createBlockCipher()->decrypt($encrypted));

if (!empty($_GET['value'])) {
    echo sprintf('<p>Decrypted value: %s</p>', createBlockCipher()->decrypt($_GET['value']));
} else {
    echo sprintf('<p>Decrypted value: <a href="?value=%s">Load from url</a></p>', '3bf53b4c29cb53ae88349e795d8ec11e75446ee942f040c04e381ee097a0f30c35IT6/GgZUlsxDQtfMnN4wPZuoX3TAa3yvxwyKH5cTXSgkVpHU7J6Y2mdSVG3T6A');
}
