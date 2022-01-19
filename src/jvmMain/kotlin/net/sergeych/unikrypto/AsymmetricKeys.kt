package net.sergeych.unikrypto

import com.icodici.crypto.HashType

fun HashAlgorithm.toUnicrypto(): HashType =
    when (this) {
        HashAlgorithm.SHA3_384 -> HashType.SHA3_384
        HashAlgorithm.SHA3_256 -> HashType.SHA3_256
        HashAlgorithm.SHA3_512 -> HashType.SHA3_512
        HashAlgorithm.SHA256 -> HashType.SHA256
        HashAlgorithm.SHA512 -> HashType.SHA512
    }

internal class PublicKeyImpl(private val key: com.icodici.crypto.PublicKey) :
    PublicKey() {

    override val id by lazy { BytesId(key.longAddress.packed) }

    override val bitStrength: Int = key.bitStrength

    override fun encryptBlock(plaintext: ByteArray): ByteArray = key.encrypt(plaintext)

    override fun checkSignature(data: ByteArray, signature: ByteArray, hashAlgorithm: HashAlgorithm): Boolean =
        key.verify(data, signature, hashAlgorithm.toUnicrypto())

    override val packed: ByteArray by lazy { key.pack() }
}

internal class PrivateKeyImpl(private val key: com.icodici.crypto.PrivateKey) :
    PrivateKey() {

    override val id by lazy { BytesId(key.publicKey.longAddress.packed) }

    override val publicKey by lazy { PublicKeyImpl(key.publicKey) }

    override fun decryptBlock(ciphertext: ByteArray): ByteArray = key.decrypt(ciphertext)

    override val packed: ByteArray by lazy { key.pack() }

    override fun sign(data: ByteArray, hashAlgorithm: HashAlgorithm): ByteArray =
        key.sign(data, hashAlgorithm.toUnicrypto())
}

actual val AsymmetricKeys: AsymmetricKeysProvider = object : AsymmetricKeysProvider {

    override suspend fun generate(bitStrength: Int): PrivateKey = PrivateKeyImpl(com.icodici.crypto.PrivateKey(bitStrength))

    override fun unpackPublic(data: ByteArray): PublicKey = PublicKeyImpl(com.icodici.crypto.PublicKey(data))

    override fun unpackPrivate(data: ByteArray): PrivateKey = PrivateKeyImpl(com.icodici.crypto.PrivateKey(data))
}
