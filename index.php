<?php
$data = array(
    'name' => 'Wisnu Ardianto',
    'email' => 'setrasariputra@gmail.com',
    'role' => array(
        'name' => 'Super Admin',
        'access' => 'Full Access'
    ),
);
$plaintext = json_encode($data);
$phrase = '123456789#abcdefghijklmnopqrstuvwxyz';
$method = 'aes-256-cbc';

echo "Plaintext: ".$plaintext. "<br />";

// must be exact 128 chars (512 bit)
$key = bin2hex(hash('sha512', $phrase));
echo "Key: ".$key. "<br />";

// IV must be exact 16 chars (128 bit)
$iv = str_repeat(chr(0x0), 16);

// start encrypt
$encrypted = base64_encode(openssl_encrypt($plaintext, $method, $key, OPENSSL_RAW_DATA, $iv));
echo "Encrypted: ".$encrypted. "<br />";

// start decrypt
$decrypted = openssl_decrypt(base64_decode($encrypted), $method, $key, OPENSSL_RAW_DATA, $iv);
echo "Decrypted: ".$decrypted. "<br />";
