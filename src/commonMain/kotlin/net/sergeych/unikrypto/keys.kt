package net.sergeych.unikrypto

import kotlin.random.Random

enum class HashAlgorithm {
    SHA3_256, SHA3_384
}

open class AbstractUnikey(val id: KeyIdentity,val canSign: Boolean = false,
                     val canCheckSignature: Boolean = false,
                     val canEncrypt: Boolean = false,
                     val canDecrypt: Boolean = false) {

    open suspend fun sign(data: ByteArray, hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA3_384): ByteArray =
        throw OperationNotSupported()

    suspend fun sign(text: String,hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA3_384): ByteArray
      = sign(text.encodeToByteArray(), hashAlgorithm)

    open suspend fun checkSignature(
        data: ByteArray,
        signature: ByteArray,
        hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA3_384
    ): Boolean = throw OperationNotSupported()

    suspend fun checkSignature(
        text: String,
        signature: ByteArray,
        hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA3_384
    ): Boolean = checkSignature(text.encodeToByteArray(), signature, hashAlgorithm)

    open suspend fun etaEncrypt(plaintext: ByteArray): ByteArray = throw OperationNotSupported()

    suspend fun etaEncrypt(plaintext: String): ByteArray = etaEncrypt(plaintext.encodeToByteArray())

    open suspend fun etaDecrypt(ciphertext: ByteArray): ByteArray = throw OperationNotSupported()

    suspend fun etaDecryptToString(ciphertext: ByteArray): String = etaDecrypt(ciphertext).decodeToString()

    open suspend fun pack(): ByteArray = throw OperationNotSupported()

    override fun equals(other: Any?): Boolean {
        return other != null && other is AbstractUnikey && other.id == id && other.canSign == canSign
                && other.canDecrypt == canDecrypt && other.canCheckSignature == canCheckSignature
                && other.canEncrypt == canEncrypt
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

abstract class PublicKey(id: KeyIdentity): AbstractUnikey(id, canEncrypt = true, canCheckSignature = true) {
    abstract val bitStrength: Int

    open val maxMessageSize by lazy {
        // for SHA256 or SHA3_256 overhead is:
        bitStrength/8 - 32 * 2 - 2
    }

    open val minimumEncryptedSize by lazy {
        bitStrength/8
    }

    abstract suspend fun encryptBlock(plaintext: ByteArray): ByteArray

    override suspend fun etaEncrypt(plaintext: ByteArray): ByteArray {
        if( plaintext.size <= maxMessageSize ) return encryptBlock(plaintext)
        val k = SymmetricKeys.random()
        var encodedMessage = k.pack() + k.etaEncrypt(plaintext)

        val part1 = encodedMessage.sliceArray(0 until maxMessageSize )
        val part2 = encodedMessage.sliceArray( maxMessageSize until encodedMessage.size)

        return encryptBlock(part1) + part2
    }
}

abstract class PrivateKey(id: KeyIdentity): AbstractUnikey(id, canDecrypt = true, canSign = true) {
    abstract val publicKey: PublicKey

    abstract suspend fun decryptBlock(ciphertext: ByteArray): ByteArray

    override suspend fun etaDecrypt(ciphertext: ByteArray): ByteArray {
        val pubk = publicKey
        if( ciphertext.size < pubk.minimumEncryptedSize )
            throw UnikryptoError("encrypted block is too small: ${ciphertext.size} should be >= ${pubk.minimumEncryptedSize}")
        if( ciphertext.size == pubk.minimumEncryptedSize )
            return decryptBlock(ciphertext)

        val part1 = decryptBlock(ciphertext.sliceArray(0 until pubk.minimumEncryptedSize))
        val part2 = ciphertext.slice(pubk.minimumEncryptedSize until ciphertext.size)
        val encodedMessage = part1 + part2

        val key = SymmetricKeys.create(encodedMessage.sliceArray(0 .. 31))
        return key.etaDecrypt(encodedMessage.sliceArray(32 until encodedMessage.size))
    }
}


interface AsymmetricKeysProvider {
    suspend fun generate(bitStrength: Int): PrivateKey
    suspend fun unpackPublic(data: ByteArray): PublicKey
    suspend fun unpackPrivate(data: ByteArray): PrivateKey
}

expect val AsymmetricKeys: AsymmetricKeysProvider

