package net.sergeych.unikrypto

import com.icodici.crypto.PBKDF2

actual suspend fun PerformPBKDF2(
    password: String,
    size: Int,
    hash: HashAlgorithm,
    rounds: Int,
    salt: ByteArray
): ByteArray = PBKDF2.derive(
        hash.toUnicrypto().findDigestClass(),
        password,
        salt,
        rounds,
        size)
