<?php

$plaintext = 'My password Login';
$password = '123456789#abcdefghijklmnopqrstuvwxyz';
$method = 'aes-256-cbc';

echo "Plaintext: ".$plaintext. "<br />";

// must be exact 64 chars (256 bit)
$password = hash('sha256', $password);
echo "Password: ".$password. "<br />";

// IV must be exact 16 chars (128 bit)
$iv = str_repeat(chr(0x0), 16);

// start encrypt
$encrypted = base64_encode(openssl_encrypt($plaintext, $method, $password, OPENSSL_RAW_DATA, $iv));
echo "Encrypted: ".$encrypted. "<br />";

// start decrypt
$decrypted = openssl_decrypt(base64_decode($encrypted), $method, $password, OPENSSL_RAW_DATA, $iv);
echo "Decrypted: ".$decrypted. "<br />";
