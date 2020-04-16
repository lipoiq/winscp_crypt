function WinSCP() {
  var PWALG_BYTES = [];
  var PWALG_SIMPLE_MAGIC = 0xA3;
  var PWALG_SIMPLE_STRING = '0123456789ABCDEF';
  var PWALG_SIMPLE_MAXLEN = 50;
  var PWALG_SIMPLE_FLAG = 0xFF;
  var PWALG_SIMPLE_INTERNAL = 0x00;

  function rand(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }

  function _simple_encrypt_char(char) {
    char = ~char ^ PWALG_SIMPLE_MAGIC;

    var a = (char & 0xF0) >> 4;
    var b = (char & 0x0F) >> 0;

    return [PWALG_SIMPLE_STRING[a], PWALG_SIMPLE_STRING[b]].join('');
  }

  function _simple_decrypt_next_char() {
    if (PWALG_BYTES.length == 0) {
      return PWALG_SIMPLE_INTERNAL;
    }

    var a = PWALG_SIMPLE_STRING.indexOf(PWALG_BYTES[0]);
    var b = PWALG_SIMPLE_STRING.indexOf(PWALG_BYTES[1]);

    PWALG_BYTES.shift();
    PWALG_BYTES.shift();

    return PWALG_SIMPLE_FLAG & ~(((a << 4) + b << 0) ^ PWALG_SIMPLE_MAGIC);
  }

  // Encrypt password
  this.encrypt = function(username, hostname, password) {
    var salt = username+''+hostname+''+password, shift = 0;;

    if (salt.length < PWALG_SIMPLE_MAXLEN) {
      shift = rand(0, PWALG_SIMPLE_MAXLEN - salt.length);
    }

    result = [];
    result.push(_simple_encrypt_char(PWALG_SIMPLE_FLAG));
    result.push(_simple_encrypt_char(PWALG_SIMPLE_INTERNAL));
    result.push(_simple_encrypt_char(salt.length));
    result.push(_simple_encrypt_char(shift));

    for (var i = 0; i < shift; i++) {
      result.push(_simple_encrypt_char(rand(0, 256)));
    }

    for (var i = 0; i < salt.length; i++) {
      result.push(_simple_encrypt_char(salt[i].charCodeAt(0)));
    }

    while (result.length < PWALG_SIMPLE_MAXLEN * 2) {
      result.push(_simple_encrypt_char(rand(0, 256)));
    }

    return result.join('');
  }

  // Descrypt password
  this.decrypt = function(username, hostname, password) {
    var result = [];
    var key = username+''+hostname;

    PWALG_BYTES = password.split('');

    var flag = _simple_decrypt_next_char(), length;

    if (flag == PWALG_SIMPLE_FLAG) {
      _simple_decrypt_next_char();
      length = _simple_decrypt_next_char();
    } else {
      length = flag;
    }

    PWALG_BYTES = PWALG_BYTES.slice(_simple_decrypt_next_char() * 2);

    for (var i = 0; i < length; i++) {
      result.push(String.fromCharCode(_simple_decrypt_next_char()));
    }

    if (flag == PWALG_SIMPLE_FLAG) {
      var valid = result.slice(0, key.length).join('');

      if (valid != key) {
        result = [];
      } else {
        result = result.slice(key.length);
      }
    }

    PWALG_BYTES = [];

    return result.join('');
  }
}
