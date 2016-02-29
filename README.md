# kCryptFS
kCryptFS is a very simple, FUSE-based crypto filesystem supporting various ciphers provided by
e.g. OpenSSL or the kernel's crypto API.

While many test-cases are available, the filesystem is NOT intended for production use.
However, you can get an insight how FUSE and file-encryption works.

## compile it

```
# 1) choose a folder
cd /tmp

# 2) clone the project
git clone https://github.com/k-a-z-u/kCryptFS

# 3) create a build folder
mkdir build
cd build

# 4) run CMake
cmake ../kCryptFS

# 5) chose your configuration
# you should select "WITH_OPENSSL" and "WITH_TESTS"
ccmake ../kCryptFS

# 6) build
make
```

## use it

### run tests

Before you mount anything, you should run the included test-cases. To do so, just execute the following command:

`kCryptFS -test`

### mount
To mount a folder `/tmp/enc` containing encrypted data to its unencrypted counterpart `/tmp/dec`, use the following commandline:
```
./kCryptFS -foreground --cipher-filedata=openssl_aes_cbc_256 --cipher-filename=openssl_aes_cbc_256 \
  --key-derivation=openssl_pbkdf2_sha256 --iv-gen=openssl_sha256 /tmp/enc /tmp/dec
```
As you can see, all algorithms (cipher, key-derivation, IV-generator) are (currently) provided as command-line arguments. The availability depends on above CMake configuration (openSSL, kernel, ...). If you omit those arguments, you will get a list of available ciphers, etc.

If everything is fine, kCryptFS asks for two passwords: one for the file-data encryption and one for the file-name encryption. For a better security, you SHOULD use two different passwords! However, if you are not paranoid, you can just omit the 2nd, which uses the same as the 1st one.

Those passwords are then used to derive strong keys using the provided key derivation function.

Finally, file-names and file-data are encrypted using those derived keys together with the selected cipher and IV-generator.
