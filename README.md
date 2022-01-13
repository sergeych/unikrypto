# Mulltiplatform universa cryptolibrary

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> __beta stage__ yet, testing in a commercial project. 

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
    implementation("net.sergeych:unikrypto:1.0-SNAPSHOT")
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

**works the same in browser, desktop, server and node.js**. Now you can share your code slmost everywhere. Native support is planned (there are C++ libraries fro it, buy C binding are required by kotlin native).

**Coroutine support on both platforms**. In Kotlin JS many slow processes are scheduled to run in the worker, not blocking calling thread. All JS stiff is hidden under suspend functions (coroutines).

**Advanced key types approach**: separate interfaces for encrypting, decrypting, signing and verifying keys allows using symmetric and asymmetric keys the same way where appropriate.

**Smart EtA encryption for public keys**. It is possible to encrypt long plaintext with private keys with a minimal overhead. The encryption is binary compatible with universa one as long as all the data fit the private key block. Longer data is automatically wrapped into a radnom key encrypted container that is partially placed in the private key encrypted block and the rest is appended to it. Minimal overhead, no headache.

**Generalized key identities**: modern alternative to key fingerprints less ancient key addresses, takes the best of these two in the kotlin style: convenient tool to organize, compare and find keys without weakening the identified keys.

**Signed records with serialization support** using kotlinx serialization and [boss-serialization-mp](https://github.com/sergeych/boss-serialization-mp).

## Roadmap

As futher Universa development will be performed in kotlin on browser, andorid, desktop, server and (soon) iOS platforms, all new cryptographic primitives and functions will be added to this library ot be shared with all platforms and the society.

## LICENSE

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
