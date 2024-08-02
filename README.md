# EOS-ECC-csharp

This library was developed to solve one problem of signing and verifying signatures using keys created in EOSIO. The third-party libraries used in the project have been modified for EOSIO.
The author does not guarantee the further development of the library, but as necessary, you can modify it to suit your needs

# Example

```
using eos_ecc;
string eosSign = ApiCommon.SignData("hi its me", "5JPdD1QWzrWRQqHcSHLJv9XWtyEah9SncCmN1nj1DxVxjCeuxyi");
bool resVerifySign = ApiCommon.VerifySignature(b.ToString(), "hi its me", "EOS6AzHKdnoELKmqHrQmbxwDvDGQ8ZKtQiuBNcZinZ5b3xJ5oX1U5");
```