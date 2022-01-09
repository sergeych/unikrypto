package net.sergeych.unikrypto

import kotlin.random.Random

enum class HashAlgorithm {
    SHA3_256, SHA3_384
}

interface KeyIdentity {
    fun matches(obj: Any): Boolean
    val asByteArray: ByteArray
    val asString: String
}

abstract class GenericKeyIdentity: KeyIdentity {
    override fun equals(other: Any?): Boolean = other?.let { matches(it) } ?: false
}

class BytesId(val id: ByteArray): GenericKeyIdentity() {
    override fun matches(obj: Any): Boolean {
        return (obj is BytesId) && obj.id contentEquals id
    }
    override val asByteArray: ByteArray
        get() = id
    override val asString: String
        get() = id.toBase64Compact()

    companion object {
        fun fromString(data: String) = BytesId(data.decodeBase64Compact())
    }
}

open class AbstractUnikey(val id: KeyIdentity,val canSign: Boolean = false,
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

    override fun equals(other: Any?): Boolean {
        return other != null && other is AbstractUnikey && other.id == id
    }

}

open class SymmetricKey(id: BytesId): AbstractUnikey(id, canEncrypt = true, canDecrypt = true) {
    constructor(id: ByteArray) : this(BytesId(id))
}

interface SymmetricKeyProvider {
    fun create(keyBytes: ByteArray,id: ByteArray = Random.Default.nextBytes(32)): SymmetricKey
    fun random(): SymmetricKey
}

expect val SymmetricKeys: SymmetricKeyProvider

//open class PrivateKey(id: ByteArray): AbstractUnikey(id, canDecrypt = true, canSign = true)
//
//open class PublicKey(id: ByteArray): AbstractUnikey(id, canEncrypt = true, canCheckSignature = true)
//
//interface PublickKeyProvider {
//
//}

