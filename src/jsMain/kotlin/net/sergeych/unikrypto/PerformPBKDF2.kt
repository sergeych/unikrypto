package net.sergeych.unikrypto

import kotlinx.coroutines.await

actual suspend fun PerformPBKDF2(
    password: String,
    size: Int,
    hash: HashAlgorithm,
    rounds: Int,
    salt: ByteArray
): ByteArray = Unicrypto.pbkdf2(
    hash.toUniversa(),
    PBKDF2Params(
        rounds,
        size,
        password,
        salt.toUint8Array()
    )
).await().toByteArray()