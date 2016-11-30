<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <title>AES Test</title>
        <script type="text/javascript" src="../bower_components/crypto-js/crypto-js.js"></script>
        <script type="text/javascript">

            var salt = CryptoJS.lib.WordArray.random(16);
            var iv = CryptoJS.lib.WordArray.random(16);

            var key256Bits = CryptoJS.PBKDF2('password', salt, {
                keySize: 256 / 32,
                iterations: 5000,
                hasher: CryptoJS.algo.SHA256
            });

            var encrypted = CryptoJS.AES.encrypt('hello world', key256Bits, {
                iv: iv,
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7,
                hasher: CryptoJS.algo.SHA256
            });

            var hash = CryptoJS.HmacSHA256('hello world', 'password');
            var hashInBase64 = CryptoJS.enc.Base64.stringify(hash);

            console.log(encrypted);
            console.log(encrypted.toString());
            console.log(hashInBase64);

            var decrypted = CryptoJS.AES.decrypt(encrypted, key256Bits, {
                iv: iv,
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7,
                hasher: CryptoJS.algo.SHA256

            });

            console.log(decrypted.toString(CryptoJS.enc.Utf8));

        </script>
    </head>
    <body>

        <p>
            See the console for the result.
        </p>

    </body>
</html>
