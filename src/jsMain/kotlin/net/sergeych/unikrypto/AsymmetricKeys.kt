package net.sergeych.unikrypto

import kotlinx.coroutines.await
import org.khronos.webgl.Uint8Array

private val defaultOAEPOptions = OAEPOptions()

internal class PublicKeyImpl(private val key: Unicrypto.PublicKey) : PublicKey() {
    override val id: KeyIdentity by lazy { BytesId(key.longAddress.asBinary.toByteArray()) }

    override val bitStrength: Int by lazy { key.getBitStrength() }

    override fun encryptBlock(plaintext: ByteArray): ByteArray =
        key.encryptSync(plaintext, defaultOAEPOptions).toByteArray()

    override val packed by lazy { key.packed.toByteArray() }

    override fun checkSignature(data: ByteArray, signature: ByteArray, hashAlgorithm: HashAlgorithm): Boolean
        = key.verifySync(data, signature, SigningOptions(pssHash = hashAlgorithm.toUniversa()))
}

internal class PrivateKeyImpl(private val key: Unicrypto.PrivateKey) : PrivateKey() {

    override val id: KeyIdentity by lazy { BytesId(key.publicKey.longAddress.asBinary.toByteArray()) }

    override val publicKey: PublicKey by lazy { PublicKeyImpl(key.publicKey) }

    override fun decryptBlock(ciphertext: ByteArray): ByteArray =
        key.decryptSync(ciphertext, defaultOAEPOptions).toByteArray()

    override val packed: ByteArray by lazy { key.packSync() }

    override fun sign(data: ByteArray, hashAlgorithm: HashAlgorithm): ByteArray
        = key.signSync(data,SigningOptions(pssHash = hashAlgorithm.toUniversa())).toByteArray()
}

fun ByteArray.toUint8Array(): Uint8Array = Uint8Array(this.toTypedArray())

actual val AsymmetricKeys: AsymmetricKeysProvider = object : AsymmetricKeysProvider {
    override suspend fun generate(bitStrength: Int): PrivateKey =
        PrivateKeyImpl(Unicrypto.PrivateKey.generate(PrivateKeyParams(bitStrength)).await())

    override fun unpackPublic(data: ByteArray): PublicKey
        = PublicKeyImpl(Unicrypto.PublicKey.unpackSync(data))

    override fun unpackPrivate(data: ByteArray): PrivateKey
        = PrivateKeyImpl(Unicrypto.PrivateKey.unpackSync(data.toUint8Array()))
}