# Multiplatform universa cryptolibrary

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> __RC2 stage__ used in production systems.

## Current version

We recommend `1.2.4-rc1`

__1.2.*__ version are to use with __kotlin 1.7__. 

A new generation of cryptographic primitives that origins in the universa projects now in form of kotlin multiplatform library. It effectively works in 

- kotlin JS (using fast wasm)
- kotlin JVM

Kotlin native support is in plans.

## Installation

Use gradle maven dependency. First add our repository:

~~~
repositories {
    // ...
    maven("https://maven.universablockchain.com/")
}
~~~

Add dependency to where needed:

~~~
dependencies {
    //...  
    implementation("net.sergeych:unikrypto:1.1.1")
}
~~~

## Usage

~~~kotlin
import net.sergeych.unikrypto.*

@Serializable
data class MyProtectedData(value: Int)

suspend fun sampleSign(text: String): Pair<PrivateKey,ByteArray> {
    val key = AsymmetricKeys.generate(2048)
    return key to key.sign(text)
    
    val data = MyProtectedData(42)
    val packedSignedRecord = key.signRecord(data)
    val sr = SignedRecord.unpack(packed)
    assertEquals(data, sr.decode())
    assertTrue(key.id == sr.publicKey.id)
}
~~~

## Features

**works the same in browser, desktop, server and node.js**. Now you can share your code almost everywhere. Native support is planned (there are C++ libraries for it, buy C binding are required by kotlin native).

**Coroutine support on both platforms**. In Kotlin JS many slow processes are scheduled to run in the worker, not blocking calling thread. All JS stiff is hidden under suspend functions (coroutines).

**Advanced key types approach**: separate interfaces for encrypting, decrypting, signing and verifying keys allows using symmetric and asymmetric keys the same way where appropriate.

**Smart EtA encryption for public keys**. It is possible to encrypt long plaintext with private keys with a minimal overhead. The encryption is binary compatible with universa one as long as all the data fit the private key block. Longer data is automatically wrapped into a random key encrypted container that is partially placed in the private key encrypted block and the rest is appended to it. Minimal overhead, no headache.

**Generalized key identities**: modern alternative to key fingerprints less ancient key addresses, takes the best of these two in the kotlin style: convenient tool to organize, compare and find keys without weakening the identified keys.

**Signed records with serialization support** using kotlinx serialization and [boss-serialization-mp](https://github.com/sergeych/boss-serialization-mp).

**serialization-aware SignedRecord**: easy to use with your serializable payload

**keyrings** for any type of keys to work simultaneously 

**containers** serialization-firendly multikey containers based on keyrings.

**Encrypted KVStorages** easy to use and really safe even in browser target. See below.

### Encrtypted storages

The KV storages that uses serialization and boss encoders are part of [boss-serialization-mp](https://github.com/sergeych/boss-serialization-mp) we use end expose here. This library provides implementation to encrypt keys and values on the fly that allows using it even in the browser `localStorage` or `sessionStorage` easily. The browser storage backend is already included in `boss-serialization-mp`, and for JVM we provide MapDB based sample, not included into library, to acoid MapDB dependency, see `/code_snippets`. For android targets we still recommend to write a backend based on `SharedProperties`.

Sometimes it is convenient to switch to encrypted storage on the fly. In this case use [BindableBinaryStorage] included in the library, it allows changing a backing storage on the fly.

## Latest Changes

### 1.2.4-rc2
- improved and fixed key addresses suuport for asymmetrics
- added key addresses, same as in Universa
- added keyrings
- added containers that also support non-identifiable symmetric keys
- added Diffie-Hellman support
- added Safe58 support with crc-guarded contents

### 1.2.1-SNAPSHOT
- many fixes and improvements
- support for key address decoding in `AsymmetricKeys` provider.

### 1.1.0-SNAPSHOT

- Introduced `AheadPrivateKeyGenerator` class to generate private keys in bacground ahead of time
- Added platform based mutex surrogate that performs that uses mutex on JVM and does nothing on JS. Strange times require strange deeds.
- Added `EncryptedBinaryStorage`, `EncryptedStorage` and `BindableBinaryStorage`: infrastructure to effectively keep encrypted keys and values in KV storage
- Added `KeyAddress` support, which incorporates address integrity check
- Private and public keys now use  KeyAdddress-based `AddressId` identity, more safe. This change in most cases is compatible with existing code, see `AddressId` class for more.
- Added compatibility method to pack and unpack universa encrypted private key files.

## Roadmap

As further Universa development will be performed in kotlin on browser, android, desktop, server and (soon) iOS platforms, all new cryptographic primitives and functions will be added to this library ot be shared with all platforms and the society.

## Thanks

- _QuickBirdEng_ for [native kotlin CRC implementations](https://github.com/QuickBirdEng/crc-kotlin)

## LICENSE

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
