## PKCS #11 Runners for Project Wycheproof

**This project is experimental and comes with no guaranteed support or SLA.**

This project enables running the Project Wycheproof test vectors on PKCS #11 devices. It should compile and run on any modern Linux system with a PKCS #11 compliant device.

## Building
### Dependencies
* libssl-dev
* libjansson-dev
* Appropriate test files downloaded from https://github.com/google/wycheproof/tree/master/testvectors

   Example files: aes_cbc_pkcs5_test.json  aes_gcm_test.json  dsa_test.json  ecdsa_test.json  rsa_signature_test.json


### Build tools
* g++
* cmake

### Steps
    git clone https://github.com/awslabs/pkcs11-runners-for-project-wycheproof.git
    mkdir build-pkcs11-runners-for-project-wycheproof && cd build-pkcs11-runners-for-project-wycheproof
    cmake ../pkcs11-runners-for-project-wycheproof
    make

## Running
Running `Pkcs11RunnersForProjectWycheproof` will output usage guidance.
    Usage: ./Pkcs11RunnersForProjectWycheproof -l libraryPath -s slotNum -p PIN <-i ignoredFlag1> <-i ignoredFlag2> <testVectors...>
    
### Required parameters
* `-l` path to the library (.so file) providing the PKCS #11 impementation
* `-s` PKCS #11 slot number to test
* `-p` SO PIN
* `<testVectors>...` One or more JSON files from Project Wycheproof. Must be last parameters

### Optional Parameters
* `-i` flag (as defined in a JSON test file) which will cause a given test to be skipped if present (may be repeated)

## Supported algorithms
As defined by the "algorithm" field in test Wycheproof test files and associated PKCS #11 mechanisms

* RSASig
  * CKM_SHA1_RSA_PKCS
  * CKM_SHA256_RSA_PKCS
* DSA
  * CKM_DSA_SHA1
  * CKM_DSA_SHA224
  * CKM_DSA_SHA256
* ECDSA
  * CKM_ECDSA_SHA1
  * CKM_ECDSA_SHA224
  * CKM_ECDSA_SHA256
  * CKM_ECDSA_SHA384
  * CKM_ECDSA_SHA512
* AES-CBC-PKCS5
  * CKM_AES_CBC_PAD
* AES-GCM
  * CKM_AES_GCM
* RSASSA-PSS
  * CKM_SHA_1
  * CKM_SHA224
  * CKM_SHA256
  * CKM_SHA384
  * CKM_SHA512

## License

This library is licensed under the Apache 2.0 License. 
