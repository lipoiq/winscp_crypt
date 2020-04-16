# WinSCP Password Encrypt/Decrypt

## Simple usage

```var WinSCP = new WinSCP();

var user = 'root';
var host = '127.0.0.1';
var pass = 'qwerty123';

var encrypted = WinSCP.encrypt(user, host, pass);
var decrypted = WinSCP.decrypt(user, host, encrypted);

console.log(encrypted);
console.log(decrypted);```
