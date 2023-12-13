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
##SM4(128)
Usage: ./sm4_xts <-e|-d> <SM4_key> <IV> <input_text_or_ciphertext>
##AES(256)
Usage: ./xts_debug <-e|-d> <AES_key> <IV> <input_text_or_ciphertext>

