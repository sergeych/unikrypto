package net.sergeych.unikrypto

import com.icodici.crypto.HashType
import com.icodici.crypto.KeyAddress

internal class KeyAdddressIdentity(val address: KeyAddress) : GenericKeyIdentity() {
    override fun matches(obj: Any): Boolean = when (obj) {
        is KeyAddress -> address.isMatchingKeyAddress(obj)
        is KeyAdddressIdentity -> address.isMatchingKeyAddress(obj.address)
        is IdentifiableKey -> obj.id.matches(this)
        is com.icodici.crypto.PrivateKey -> obj.isMatchingKeyAddress(address)
        is com.icodici.crypto.PublicKey -> obj.isMatchingKeyAddress(address)
        else -> false
    }

    override val asByteArray: ByteArray = address.packed
    override val asString: String = address.toString()
}

fun HashAlgorithm.toUnicrypto(): HashType =
    when (this) {
        HashAlgorithm.SHA3_384 -> HashType.SHA3_384
        HashAlgorithm.SHA3_256 -> HashType.SHA3_256
    }

internal class PublicKeyImpl(private val key: com.icodici.crypto.PublicKey) :
    PublicKey(KeyAdddressIdentity(key.longAddress)) {

    override val bitStrength: Int = key.bitStrength

    override suspend fun encryptBlock(plaintext: ByteArray): ByteArray = key.encrypt(plaintext)

    override suspend fun checkSignature(data: ByteArray, signature: ByteArray, hashAlgorithm: HashAlgorithm): Boolean =
        key.verify(data, signature, hashAlgorithm.toUnicrypto())

    override suspend fun pack(): ByteArray = key.pack()
}

internal class PrivateKeyImpl(private val key: com.icodici.crypto.PrivateKey) :
    PrivateKey(KeyAdddressIdentity(key.publicKey.longAddress)) {

    override val publicKey by lazy { PublicKeyImpl(key.publicKey) }

    override suspend fun decryptBlock(ciphertext: ByteArray): ByteArray = key.decrypt(ciphertext)

    override suspend fun pack(): ByteArray = key.pack()

    override suspend fun sign(data: ByteArray, hashAlgorithm: HashAlgorithm): ByteArray =
        key.sign(data, hashAlgorithm.toUnicrypto())
}

actual val AsymmetricKeys: AsymmetricKeysProvider = object : AsymmetricKeysProvider {

    override suspend fun generate(bitStrength: Int): PrivateKey = PrivateKeyImpl(com.icodici.crypto.PrivateKey(bitStrength))

    override suspend fun unpackPublic(data: ByteArray): PublicKey = PublicKeyImpl(com.icodici.crypto.PublicKey(data))

    override suspend fun unpackPrivate(data: ByteArray): PrivateKey = PrivateKeyImpl(com.icodici.crypto.PrivateKey(data))
}
