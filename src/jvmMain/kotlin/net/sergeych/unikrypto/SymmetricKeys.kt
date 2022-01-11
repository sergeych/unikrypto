package net.sergeych.unikrypto

import kotlin.random.Random

actual val SymmetricKeys: SymmetricKeyProvider = object : SymmetricKeyProvider {
    override fun create(keyBytes: ByteArray, id: ByteArray): SymmetricKey =
        SymmetricKeyImpl(id, com.icodici.crypto.SymmetricKey(keyBytes))


    override fun random(): SymmetricKey =
        SymmetricKeyImpl(Random.Default.nextBytes(32), com.icodici.crypto.SymmetricKey())
}

