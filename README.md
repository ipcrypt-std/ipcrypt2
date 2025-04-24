# `ipcrypt2`

`ipcrypt2` is a lightweight C library that encrypts (or "obfuscates") IP addresses for privacy and security purposes.

It supports both IPv4 and IPv6 addresses, and it can optionally preserve the IP format (so an IP address is still recognized as an IP address after encryption). `ipcrypt2` also provides a non-deterministic encryption mode, where encrypting the same address multiple times will yield different ciphertexts.

This is an implementation of the [Methods for IP Address Encryption and Obfuscation](https://jedisct1.github.io/draft-denis-ipcrypt/draft-denis-ipcrypt.html) draft.

## Features

- **IPv4 and IPv6 support**
  Works seamlessly with both IP address formats.

- **Format-Preserving Encryption (FPE)**
  In "standard" mode, an address is encrypted into another valid IP address. This means that consumers of the data (e.g., logs) still see what appears to be an IP address, but without revealing the original address.

- **Non-Deterministic Encryption**
  Supports non-deterministic encryption using the KIASU-BC and AES-XTX tweakable block ciphers, ensuring that repeated encryptions of the same IP produce different outputs.

- **Fast and Minimal**
  Fast and Minimal: Written in C with no external dependencies. It uses hardware-accelerated AES instructions when available for improved performance, but it also supports a software fallback on any CPU, including WebAssembly environments.

- **Convenient APIs**
  Functions are provided to encrypt/decrypt in-place (16-byte arrays for addresses) or via string-to-string conversions (e.g., `x.x.x.x` → `y.y.y.y`).

- **No Extra Heap Allocations**
  Simple usage and easy to integrate into existing projects. Just compile and link.

## Table of Contents

- [`ipcrypt2`](#ipcrypt2)
  - [Features](#features)
  - [Table of Contents](#table-of-contents)
  - [Getting Started](#getting-started)
  - [Building with a Traditional C Compiler](#building-with-a-traditional-c-compiler)
  - [Building with Zig](#building-with-zig)
  - [API Overview](#api-overview)
    - [1. `IPCrypt` Context](#1-ipcrypt-context)
    - [2. Initialization and Deinitialization](#2-initialization-and-deinitialization)
    - [3. Format-Preserving Encryption / Decryption](#3-format-preserving-encryption--decryption)
    - [4. Non-Deterministic Encryption / Decryption](#4-non-deterministic-encryption--decryption)
      - [With 8 Byte Tweaks (ND Mode)](#with-8-byte-tweaks-nd-mode)
      - [With 16 Byte Tweaks (NDX Mode)](#with-16-byte-tweaks-ndx-mode)
    - [5. Helper Functions](#5-helper-functions)
  - [Examples](#examples)
    - [Format-Preserving Example](#format-preserving-example)
    - [Non-Deterministic Example](#non-deterministic-example)
  - [Security Considerations](#security-considerations)
  - [Limitations and Assumptions](#limitations-and-assumptions)
  - [Bindings and Other Implementations](#bindings-and-other-implementations)

## Getting Started

1. **Download/Clone** this repository.
2. **Include** the library's files (`ipcrypt2.c` and `ipcrypt2.h`) in your project.
3. **Build** and link them with your application, either via a traditional compiler or through Zig.

## Building with a Traditional C Compiler

An example using GCC or Clang might look like:

```sh
# 1. Compile the library
gcc -c -O2 ipcrypt2.c -o ipcrypt2.o

# 2. Compile your application and link with the library object
gcc -O2 myapp.c ipcrypt2.o -o myapp
```

If you are cross-compiling for ARM, make sure your toolchain targets AES-enabled ARM CPUs and sets the appropriate flags.

## Building with Zig

Zig can compile and link C code. You can typically build the project by running:

```sh
zig build -Doptimize=ReleaseFast
```

or

```sh
zig build -Doptimize=ReleaseSmall
```

The resulting library and headers will be placed into the `zig-out` directory.

## API Overview

All user-facing declarations are in **ipcrypt2.h**. Here are the key structures and functions:

### 1. `IPCrypt` Context

```c
typedef struct IPCrypt { ... } IPCrypt;
```

- Must be initialized via `ipcrypt_init()` with a 16-byte key.
- Optionally, call `ipcrypt_deinit()` to zero out secrets in memory once done.

### 2. Initialization and Deinitialization

```c
void ipcrypt_init(IPCrypt *ipcrypt, const uint8_t key[IPCRYPT_KEYBYTES]);
void ipcrypt_deinit(IPCrypt *ipcrypt);
```

- **Initialization** loads the user-provided AES key and prepares the context.
- **Deinitialization** scrubs sensitive data from memory.

### 3. Format-Preserving Encryption / Decryption

```c
// For 16-byte (binary) representation of IP addresses:
void ipcrypt_encrypt_ip16(const IPCrypt *ipcrypt, uint8_t ip16[16]);
void ipcrypt_decrypt_ip16(const IPCrypt *ipcrypt, uint8_t ip16[16]);

// For string-based IP addresses:
size_t ipcrypt_encrypt_ip_str(const IPCrypt *ipcrypt,
                              char encrypted_ip_str[IPCRYPT_MAX_IP_STR_BYTES],
                              const char *ip_str);

size_t ipcrypt_decrypt_ip_str(const IPCrypt *ipcrypt,
                              char ip_str[IPCRYPT_MAX_IP_STR_BYTES],
                              const char *encrypted_ip_str);
```

- **`ipcrypt_encrypt_ip16`** / **`ipcrypt_decrypt_ip16`**: In-place encryption/decryption of a 16-byte buffer. An IPv4 address must be placed inside a 16-byte buffer as an IPv4-mapped IPv6.
- **`ipcrypt_encrypt_ip_str`** / **`ipcrypt_decrypt_ip_str`**: Takes an IP string (IPv4 or IPv6), encrypts it as a new IP, and returns the encrypted address as a string. Decryption reverses that process.

### 4. Non-Deterministic Encryption / Decryption

#### With 8 Byte Tweaks (ND Mode)

```c
void ipcrypt_nd_encrypt_ip16(const IPCrypt *ipcrypt,
                             uint8_t ndip[IPCRYPT_NDIP_BYTES],
                             const uint8_t ip16[16],
                             const uint8_t random[IPCRYPT_TWEAKBYTES]);

void ipcrypt_nd_decrypt_ip16(const IPCrypt *ipcrypt,
                             uint8_t ip16[16],
                             const uint8_t ndip[IPCRYPT_NDIP_BYTES]);

void ipcrypt_nd_encrypt_ip_str(const IPCrypt *ipcrypt,
                               char encrypted_ip_str[IPCRYPT_NDIP_STR_BYTES],
                               const char *ip_str,
                               const uint8_t random[IPCRYPT_TWEAKBYTES]);

size_t ipcrypt_nd_decrypt_ip_str(const IPCrypt *ipcrypt,
                                 char ip_str[IPCRYPT_MAX_IP_STR_BYTES],
                                 const char *encrypted_ip_str);
```

- **Non-deterministic** mode takes a random 8-byte tweak (`random[IPCRYPT_TWEAKBYTES]`).
- Even if you encrypt the same IP multiple times with the same key, encrypted values will not be unique, which helps mitigate traffic analysis or repeated-pattern attacks.
- This mode is _not_ format-preserving: the output is 24 bytes (or 48 hex characters).

#### With 16 Byte Tweaks (NDX Mode)

```c
typedef struct IPCryptNDX { ... } IPCryptNDX;

void ipcrypt_ndx_init(IPCryptNDX *ipcrypt,
                      const uint8_t key[IPCRYPT_NDX_KEYBYTES]);

void ipcrypt_ndx_deinit(IPCryptNDX *ipcrypt);

void ipcrypt_ndx_encrypt_ip16(const IPCryptNDX *ipcrypt,
                              uint8_t ndip[IPCRYPT_NDX_NDIP_BYTES],
                              const uint8_t ip16[16],
                              const uint8_t random[IPCRYPT_NDX_TWEAKBYTES]);

void ipcrypt_ndx_decrypt_ip16(const IPCryptNDX *ipcrypt,
                              uint8_t ip16[16],
                              const uint8_t ndip[IPCRYPT_NDX_NDIP_BYTES]);

void ipcrypt_ndx_encrypt_ip_str(const IPCryptNDX *ipcrypt,
                                char encrypted_ip_str[IPCRYPT_NDX_NDIP_STR_BYTES],
                                const char *ip_str,
                                const uint8_t random[IPCRYPT_NDX_TWEAKBYTES]);

size_t ipcrypt_ndx_decrypt_ip_str(const IPCryptNDX *ipcrypt,
                                  char ip_str[IPCRYPT_MAX_IP_STR_BYTES],
                                  const char *encrypted_ip_str);
```

- The **NDX non-deterministic** mode takes a random 16-byte tweak (`random[IPCRYPT_NDK_TWEAKBYTES]`) and a 32-byte key (`IPCRYPT_NDX_KEYBYTES`).
- Even if you encrypt the same IP multiple times with the same key, encrypted values will not be unique, which helps mitigate traffic analysis or repeated-pattern attacks.
- This mode is _not_ format-preserving: the output is 32 bytes (or 64 hex characters).

The NDX mode is similar to the ND mode, but larger tweaks make it even more difficult to detect repeated IP addresses. The downside is that it runs at half the speed of ND mode and produces larger ciphertexts.

### 5. Helper Functions

```c
int ipcrypt_str_to_ip16(uint8_t ip16[16], const char *ip_str);
size_t ipcrypt_ip16_to_str(char ip_str[IPCRYPT_MAX_IP_STR_BYTES], const uint8_t ip16[16]);
int ipcrypt_sockaddr_to_ip16(uint8_t ip16[16], const struct sockaddr *sa);
void ipcrypt_ip16_to_sockaddr(struct sockaddr_storage *sa, const uint8_t ip16[16]);
int ipcrypt_key_from_hex(uint8_t *key, size_t key_len, const char *hex, size_t hex_len);
```

- **`ipcrypt_str_to_ip16`** / **`ipcrypt_ip16_to_str`**: Convert between string IP addresses and their 16-byte representation.
- **`ipcrypt_sockaddr_to_ip16`**: Convert a socket address structure to a 16-byte binary IP representation. Supports both IPv4 (`AF_INET`) and IPv6 (`AF_INET6`) socket addresses. For IPv4 addresses, they are converted to IPv4-mapped IPv6 format. Returns `0` on success, or `-1` if the address family is not supported.
- **`ipcrypt_ip16_to_sockaddr`**: Convert a 16-byte binary IP address to a socket address structure. The socket address structure is populated based on the IP format: for IPv4-mapped IPv6 addresses, an IPv4 socket address is created; for other IPv6 addresses, an IPv6 socket address is created. The provided `sockaddr_storage` structure is guaranteed to be large enough to hold any socket address type.
- **`ipcrypt_key_from_hex`**: Convert a hexadecimal string to a secret key. The input string must be exactly 32 or 64 characters long (16 or 32 bytes in hex). Returns `0` on success, or `-1` if the input string is invalid or conversion fails.

## Examples

Below are two illustrative examples of using `ipcrypt2` in C.

### Format-Preserving Example

```c
#include <stdio.h>
#include <string.h>
#include "ipcrypt2.h"

int main(void) {
    // A 16-byte AES key (for demonstration only; keep yours secret!)
    const uint8_t key[IPCRYPT_KEYBYTES] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    // Example IP (could be IPv4 or IPv6)
    const char *original_ip = "192.168.0.100";  // or "::1"

    IPCrypt ctx;
    ipcrypt_init(&ctx, key);

    // Encrypt
    char encrypted_ip[IPCRYPT_MAX_IP_STR_BYTES];
    ipcrypt_encrypt_ip_str(&ctx, encrypted_ip, original_ip);

    // Decrypt
    char decrypted_ip[IPCRYPT_MAX_IP_STR_BYTES];
    ipcrypt_decrypt_ip_str(&ctx, decrypted_ip, encrypted_ip);

    // Print results
    printf("Original IP : %s\n", original_ip);
    printf("Encrypted IP: %s\n", encrypted_ip);
    printf("Decrypted IP: %s\n", decrypted_ip);

    // Clean up
    ipcrypt_deinit(&ctx);
    return 0;
}
```

### Non-Deterministic Example

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "ipcrypt2.h"

int main(void) {
    // A 16-byte AES key
    const uint8_t key[IPCRYPT_KEYBYTES] = {
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00
    };
    IPCrypt ctx;
    ipcrypt_init(&ctx, key);

    // We'll generate a random 8-byte tweak
    uint8_t random_tweak[IPCRYPT_TWEAKBYTES];
    arc4random_buf(random_tweak, sizeof IPCRYPT_TWEAKBYTES);

    // Input IP
    const char *original_ip = "2607:f8b0:4005:805::200e"; // example IPv6

    // Encrypt string in non-deterministic mode
    char nd_encrypted_str[IPCRYPT_NDIP_STR_BYTES];
    ipcrypt_nd_encrypt_ip_str(&ctx, nd_encrypted_str, original_ip, random_tweak);

    // Decrypt
    char decrypted_ip[IPCRYPT_MAX_IP_STR_BYTES];
    ipcrypt_nd_decrypt_ip_str(&ctx, decrypted_ip, nd_encrypted_str);

    printf("Original IP : %s\n", original_ip);
    printf("ND-Encrypted: %s\n", nd_encrypted_str);
    printf("Decrypted IP: %s\n", decrypted_ip);

    ipcrypt_deinit(&ctx);
    return 0;
}
```

## Security Considerations

1. **Key Management**

   - You must provide a secure 16-byte AES key. Protect it and ensure it remains secret.
   - Keys should be frequently rotated.

2. **Tweak Randomness** (for non-deterministic modes)

   - **ND mode**: the 8-byte tweak does not need to be secret; however, it should be random or unique for each encryption to prevent predictable patterns. While collisions may become become a statistical concern after approximately 2^32 encryptions of the same IP address with the same key, they do not directly expose the IP address without the key.
   - **NDX mode**: the 16-byte tweak does not need to be secret; however, it should be random or unique for each encryption to prevent predictable patterns. Collisions become a statistical concern after approximately 2^64 encryptions of the same IP address with the same key. They only reveal the fact that an IP address was observed multiple times, but not the IP address itself.

3. **IP Format Preservation**

   - In "standard" mode, the library encrypts a 16-byte IP buffer into another 16-byte buffer. After encryption, it _may become a valid IPv6 address even if the original address was IPv4_, or vice versa.

4. **Not a General Purpose Encryption Library**
   - This library is specialized for IP address encryption and may not be suitable for arbitrary data encryption.

## Limitations and Assumptions

- **Architecture**: Optimized for x86_64 and ARM (aarch64) with hardware AES, but fully functional on any CPU using a software fallback. WebAssembly is also supported.
- **Format-Preserving**: Standard encryption is format-preserving at the 16-byte level. However, an original IPv4 may decrypt to an IPv6 format (or vice versa) in string form.

## Bindings and Other Implementations

- Rust bindings and a pure Rust implementation for `ipcrypt2` are available, enabling Rust developers to easily integrate and utilize the library. You can find them at [`rust-ipcrypt2`](https://crates.io/crates/ipcrypt2).
- An [implementation in JavaScript](https://www.npmjs.com/package/ipcrypt) is available on NPM.
- An [implementation in Go](https://github.com/jedisct1/go-ipcrypt) is also available.
- An [implementation in Zig](https://github.com/jedisct1/zig-ipcrypt) is also available.
- [Bindings for D](https://github.com/kassane/d-ipcrypt2) are available. Contributed by @kassane, thanks!

---

**Enjoy using `ipcrypt2`!** Contributions and bug reports are always welcome. Feel free to open issues or submit pull requests on GitHub to help improve the library.
