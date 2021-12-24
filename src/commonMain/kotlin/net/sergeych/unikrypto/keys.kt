package net.sergeych.unikrypto

enum class HashAlgorithm {
    SHA3_256, SHA3_384
}

open class AbstractUnikey(val id: ByteArray,val canSign: Boolean = false,
                     val canCheckSignature: Boolean = false,
                     val canEncrypt: Boolean = false,
                     val canDecrypt: Boolean = false) {

    open fun sign(data: ByteArray, hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA3_384): ByteArray =
        throw OperationNotSupported()

    open fun checkSignature(
        data: ByteArray,
        signature: ByteArray,
        hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA3_384
    ): Boolean = throw OperationNotSupported()

    open fun etaEncrtypt(plaintext: ByteArray): ByteArray = throw OperationNotSupported()

    fun etaEncrypt(plaintext: String): ByteArray = etaEncrtypt(plaintext.encodeToByteArray())

    open fun etaDecrypt(ciphertext: ByteArray): ByteArray = throw OperationNotSupported()

    fun etaDecryptToString(ciphertext: ByteArray): String = etaDecrypt(ciphertext).decodeToString()
}

open class SymmetricKey(id: ByteArray): AbstractUnikey(id, canEncrypt = true, canDecrypt = true)

interface SymmtricKeyProvider {
    fun unpack(bits: ByteArray): SymmetricKey
    fun random(): SymmetricKey
}

expect val SymmetricKeys: SymmtricKeyProvider
