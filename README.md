# aes_rustlang
[![rust_matrix_ci](https://github.com/hukatama024e/aes_rustlang/actions/workflows/rust_matrix_ci.yml/badge.svg)](https://github.com/hukatama024e/aes_rustlang/actions/workflows/rust_matrix_ci.yml)

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