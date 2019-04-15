# aes_rustlang
[![Build status](https://ci.appveyor.com/api/projects/status/uo6o5pr9i885va5b?svg=true)](https://ci.appveyor.com/project/hukatama024e/aes-rustlang)

Advanced Encryption Standard implimented in Rust

## Feature

* Support AES encryption and decryption(not support ECB and CBC mode yet).
* Support AES128, AES192, and AES256.

## Usage

```
USAGE:
    aes_rustlang.exe <TEXT> <KEYS>

OPTIONS:
    -k, --key_length <KEY_LENGTH>        Key length parameter [default: aes128]  [possible values: aes128, aes192,
                                         aes256]
    -o, --operate_mode <OPERATE_MODE>    Operation mode [default: encrypt]  [possible values: encrypt, decrypt]
    -h, --help                           Prints help information
    -V, --version                        Prints version information

ARGS:
    <TEXT>    Plain text for encryption or encrypted text for decryption
    <KEYS>    Keys for encryption or decryption
```

## Download
Download the [latest release].

## Licence
[MIT License]

[latest release]: https://github.com/hukatama024e/aes_rustlang/releases
[MIT License]:    LICENSE