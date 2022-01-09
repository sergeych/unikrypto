package net.sergeych.unikrypto

import kotlin.random.Random

enum class HashAlgorithm {
    SHA3_256, SHA3_384
}

open class AbstractUnikey(val id: ByteArray,val canSign: Boolean = false,
                     val canCheckSignature: Boolean = false,
                     val canEncrypt: Boolean = false,
                     val canDecrypt: Boolean = false) {

    open suspend fun sign(data: ByteArray, hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA3_384): ByteArray =
        throw OperationNotSupported()

    open suspend fun checkSignature(
        data: ByteArray,
        signature: ByteArray,
        hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA3_384
    ): Boolean = throw OperationNotSupported()

    open suspend fun etaEncrypt(plaintext: ByteArray): ByteArray = throw OperationNotSupported()

    suspend fun etaEncrypt(plaintext: String): ByteArray = etaEncrypt(plaintext.encodeToByteArray())

    open suspend fun etaDecrypt(ciphertext: ByteArray): ByteArray = throw OperationNotSupported()

    suspend fun etaDecryptToString(ciphertext: ByteArray): String = etaDecrypt(ciphertext).decodeToString()

    open suspend fun keyBytes(): ByteArray = throw OperationNotSupported()

}

open class SymmetricKey(id: ByteArray): AbstractUnikey(id, canEncrypt = true, canDecrypt = true)

interface SymmetricKeyProvider {
    fun create(keyBytes: ByteArray,id: ByteArray = Random.Default.nextBytes(32)): SymmetricKey
    fun random(): SymmetricKey
}

expect val SymmetricKeys: SymmetricKeyProvider
