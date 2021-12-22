# aes_rustlang
[![Build status](https://ci.appveyor.com/api/projects/status/uo6o5pr9i885va5b?svg=true)](https://ci.appveyor.com/project/hukatama024e/aes-rustlang)

Advanced Encryption Standard implimented in Rust

## Feature

* Support AES encryption and decryption.
* Support AES128, AES192, and AES256.
* Support CMAC.

## Block cipher mode

* Support ECB and CBC mode.
* Add padding when text is multiple of the block size(32 characters).
* Support PKCS#7 padding.

## Usage

```
USAGE:
    aes_rustlang <TEXT> <KEYS>

OPTIONS:
    -i, --initilzation_vector <INITIALIZATION_VECTOR>    Initilzation vector [default: ]
    -k, --key_length <KEY_LENGTH>
            Key length parameter [default: aes128]  [possible values: aes128, aes192, aes256]

    -o, --operate_mode <OPERATE_MODE>
            Operation mode [default: encrypt]  [possible values: encrypt, decrypt, ecb-encrypt, ecb-decrypt, cbc-
            encrypt, cbc-decrypt, cmac]
    -h, --help                                           Prints help information
    -V, --version                                        Prints version information

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