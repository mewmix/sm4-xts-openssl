#Credits

Inspired by https://gist.github.com/ants/862cb941057bdb8db00c72711d2b826c#file-ssl-encrypt-c

I went about making my own tools for verification and testing against the PYCA Cryptography library in Python. 

# Install

```
git clone https://github.com/mewmix/sm4-xts-openssl
cd sm4-xts-openssl
make
```

# Usage
## SM4(128)
Usage: ./sm4_xts <-e|-d> <SM4_key> <IV> <input_text_or_ciphertext>
## AES(256)
Usage: ./xts_debug <-e|-d> <AES_key> <IV> <input_text_or_ciphertext>


# Example

## SM4
```bash
$ ./sm4_xts_debug -e 68d90424687cc2043595091a78a44ec2c639c3ecc6b14d7ac42ce74e582fa3dc 601cd97ddeb1c75bbe5865072f3dc7a8 686579667269656E64736C657473676574656E6372797074656421
>>SM4 Key (binary): 68d90424687cc2043595091a78a44ec2c639c3ecc6b14d7ac42ce74e582fa3dc
>>IV (binary): 601cd97ddeb1c75bbe5865072f3dc7a8
>>Plaintext (binary): 686579667269656e64736c657473676574656e6372797074656421
>>Ciphertext (hex): 34143fbf6cb3a97feb84f866d85e01f8d15ed03905552cb12cd567
$ ./sm4_xts_debug -d 68d90424687cc2043595091a78a44ec2c639c3ecc6b14d7ac42ce74e582fa3dc 601cd97ddeb1c75bbe5865072f3dc7a8 34143fbf6cb3a97feb84f866d85e01f8d15ed03905552cb12cd567
>>SM4 Key (binary): 68d90424687cc2043595091a78a44ec2c639c3ecc6b14d7ac42ce74e582fa3dc
>>IV (binary): 601cd97ddeb1c75bbe5865072f3dc7a8
>>Decrypted Text: heyfriendsletsgetencrypted!
```
