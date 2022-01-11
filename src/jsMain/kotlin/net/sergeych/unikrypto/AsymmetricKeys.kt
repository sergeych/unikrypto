package net.sergeych.unikrypto

import kotlinx.coroutines.await
import org.khronos.webgl.Uint8Array

internal class KeyAddressIdentity(val address: Unicrypto.KeyAddress) : GenericKeyIdentity() {
    override fun matches(obj: Any): Boolean = when (obj) {
        is IdentifiableKey -> obj.id == this
        is KeyIdentity -> obj.asString == asString
        else -> false
    }

    override val asByteArray: ByteArray
        get() = address.asBinary

    override val asString: String
        get() = address.asString

}

private val defaultOAEPOptions = OAEPOptions()

internal class PublicKeyImpl(private val key: Unicrypto.PublicKey) : PublicKey(KeyAddressIdentity(key.longAddress)) {
    override val bitStrength: Int by lazy { key.getBitStrength() }

    override suspend fun encryptBlock(plaintext: ByteArray): ByteArray =
        key.encrypt(plaintext, defaultOAEPOptions).await()

    override suspend fun pack(): ByteArray = key.pack().await()

    override suspend fun checkSignature(data: ByteArray, signature: ByteArray, hashAlgorithm: HashAlgorithm): Boolean
        = key.verify(data, signature, SigningOptions(pssHash = hashAlgorithm.toUniversa())).await()
}

internal class PrivateKeyImpl(private val key: Unicrypto.PrivateKey) : PrivateKey(KeyAddressIdentity(key.publicKey.longAddress)) {
    override val publicKey: PublicKey by lazy { PublicKeyImpl(key.publicKey) }

    override suspend fun decryptBlock(ciphertext: ByteArray): ByteArray =
        key.decrypt(ciphertext, defaultOAEPOptions).await()

    override suspend fun pack(): ByteArray = key.pack().await()

    override suspend fun sign(data: ByteArray, hashAlgorithm: HashAlgorithm): ByteArray
        = key.sign(data,SigningOptions(pssHash = hashAlgorithm.toUniversa())).await()
}

fun ByteArray.toUint8Array(): Uint8Array = Uint8Array(this.toTypedArray())

actual val AsymmetricKeys: AsymmetricKeysProvider = object : AsymmetricKeysProvider {
    override suspend fun generate(bitStrength: Int): PrivateKey =
        PrivateKeyImpl(Unicrypto.PrivateKey.generate(PrivateKeyParams(bitStrength)).await())

    override suspend fun unpackPublic(data: ByteArray): PublicKey
        = PublicKeyImpl(Unicrypto.PublicKey.unpack(data).await())

    override suspend fun unpackPrivate(data: ByteArray): PrivateKey
        = PrivateKeyImpl(Unicrypto.PrivateKey.unpack(data.toUint8Array()).await())
}