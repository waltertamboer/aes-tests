function getPhpValue(type, password, value, cb) {
    var params = {};
    params['ajax_password'] = password;
    params['ajax_' + type] = value;

    $.ajax({
        type: 'GET',
        dataType: 'json',
        data: params,
        success: cb
    });
}

function encrypt(password, msg) {
    // Get a 16 byte salt:
    var salt = CryptoJS.lib.WordArray.random(16);

    // Create a PBKDF2 hash:
    var hashSize = 8;
    var hash = CryptoJS.PBKDF2(password, salt, {
        iterations: 5000,
        hasher: CryptoJS.algo.SHA256,
        keySize: hashSize * 2
    });

    // Extract the encryption key and the HMAC key:
    var keyAES = CryptoJS.lib.WordArray.create(hash.words.slice(0, hashSize));
    var keyHMAC = CryptoJS.lib.WordArray.create(hash.words.slice(hashSize));

    // Encryption the message:
    var encrypted = CryptoJS.AES.encrypt(msg, keyAES, {
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
        hasher: CryptoJS.algo.SHA256,
        iv: salt
    });

    var cipherText = CryptoJS.lib.WordArray.create(encrypted.iv.words);
    cipherText.concat(encrypted.ciphertext);

    // Create the cipher text that we are going to create a HMAC value for:
    var hmacStr = CryptoJS.enc.Latin1.parse('aes');
    hmacStr.concat(cipherText);

    var hmac = CryptoJS.HmacSHA256(hmacStr, keyHMAC);

    var result = hmac.toString(CryptoJS.enc.Hex) + cipherText.toString(CryptoJS.enc.Base64);

    return result;
}

function decrypt(password, encrypted) {
    var hmac = encrypted.substr(0, 64);
    var cipherText = encrypted.substr(64);

    var decoded = CryptoJS.enc.Base64.parse(cipherText);
    var decodedHex = decoded.toString(CryptoJS.enc.Hex).substr(0, 16 * 2); // IV is 16 bytes
    var decodedCipher = decoded.toString(CryptoJS.enc.Hex).substr(16 * 2); // IV is 16 bytes

    var iv = CryptoJS.enc.Hex.parse(decodedHex);

    // Create a PBKDF2 hash:
    var hashSize = 8;
    var hash = CryptoJS.PBKDF2(password, iv, {
        iterations: 5000,
        hasher: CryptoJS.algo.SHA256,
        keySize: hashSize * 2,
        salt: iv
    });

    // Extract the encryption key and the HMAC key:
    var keyAES = CryptoJS.lib.WordArray.create(hash.words.slice(0, hashSize));
    var keyHMAC = CryptoJS.lib.WordArray.create(hash.words.slice(hashSize));

    // Create the cipher text that we are going to create a HMAC value for:
    var newHmacVal = CryptoJS.enc.Latin1.parse('aes');
    newHmacVal.concat(decoded);

    var newHmac = CryptoJS.HmacSHA256(newHmacVal, keyHMAC);
    var newHmacStr = CryptoJS.enc.Hex.stringify(newHmac);

    if (newHmacStr !== hmac) {
        return false;
    }
    var cipherTextRaw = CryptoJS.enc.Hex.parse(decodedCipher);

    var decrypted = CryptoJS.AES.decrypt({
        ciphertext: cipherTextRaw
    }, keyAES, {
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
        hasher: CryptoJS.algo.SHA256,
        iv: iv
    });

    return decrypted.toString(CryptoJS.enc.Latin1);
}

var password = 'password';
var message = 'This text will be encrypted with AES-256 CBC and PBKDF2!';

var encrypted = encrypt(password, message);

console.log('Message: ' + message);
console.log('Encrypted: ' + encrypted);

getPhpValue('encrypt', password, message, function (data) {
    console.log('Encrypted by zendframework/zend-crypt BlockCipher: ' + data);
    console.log('Decrypted zend-crypt hash: ' + decrypt(password, data));
});

console.log('Decrypted: ' + decrypt(password, encrypted));

getPhpValue('decrypt', password, encrypted, function (data) {
    console.log('Decrypted by zendframework/zend-crypt BlockCipher: ' + data);
});

