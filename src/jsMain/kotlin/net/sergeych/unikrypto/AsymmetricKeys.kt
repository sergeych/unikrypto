@file:Suppress("unused")

package net.sergeych.unikrypto

import kotlinx.coroutines.await
import org.khronos.webgl.Uint8Array

private val defaultOAEPOptions = OAEPOptions()

internal class PublicKeyImpl(val key: Unicrypto.PublicKey) : PublicKey() {
    override val id: KeyIdentity by lazy { AddressId(KeyAddressJs(key.longAddress)) }

    override val bitStrength: Int by lazy { key.getBitStrength() }

    override fun encryptBlock(plaintext: ByteArray): ByteArray =
        key.encryptSync(plaintext.toUint8Array(), defaultOAEPOptions).toByteArray()

    override val packed by lazy { key.packed.toByteArray() }

    override fun checkSignature(data: ByteArray, signature: ByteArray, hashAlgorithm: HashAlgorithm): Boolean
        = key.verifySync(data.toUint8Array(), signature.toUint8Array(), SigningOptions(pssHash = hashAlgorithm.toUniversa()))
}

internal class PrivateKeyImpl(val key: Unicrypto.PrivateKey) : PrivateKey() {

    override val id: KeyIdentity by lazy { AddressId(KeyAddressJs(key.publicKey.longAddress)) }

    override val publicKey: PublicKey by lazy { PublicKeyImpl(key.publicKey) }

    override suspend fun packWithPassword(password: String) = key.pack(password).await().toByteArray()

    override fun decryptBlock(ciphertext: ByteArray): ByteArray =
        key.decryptSync(ciphertext.toUint8Array(), defaultOAEPOptions).toByteArray()

    override val packed: ByteArray by lazy { key.packSync().toByteArray() }

    override fun sign(data: ByteArray, hashAlgorithm: HashAlgorithm): ByteArray
        = key.signSync(data.toUint8Array(),SigningOptions(pssHash = hashAlgorithm.toUniversa())).toByteArray()
}

fun ByteArray.toUint8Array(): Uint8Array = Uint8Array(this.toTypedArray())

actual val AsymmetricKeys: AsymmetricKeysProvider = object : AsymmetricKeysProvider {
    override suspend fun generate(bitStrength: Int): PrivateKey =
        PrivateKeyImpl(Unicrypto.PrivateKey.generate(PrivateKeyParams(bitStrength)).await())

    override fun unpackPublic(data: ByteArray): PublicKey
        = PublicKeyImpl(Unicrypto.PublicKey.unpackSync(data.toUint8Array()))

    override fun unpackPrivate(data: ByteArray): PrivateKey
        = PrivateKeyImpl(Unicrypto.PrivateKey.unpackSync(data.toUint8Array()))

    override suspend fun decryptPrivateKey(data: ByteArray, password: String): PrivateKey
        = PrivateKeyImpl(Unicrypto.PrivateKey.unpackWithPassword(data.toUint8Array(), password).await())

    override suspend fun unpackKeyId(packedKeyId: ByteArray): KeyIdentity {
        return AddressId(packedKeyId)
    }

    override suspend fun unpackKeyId(packedKeyIdString: String): KeyIdentity {
        return AddressId(decodeAddress(packedKeyIdString))
    }
}

val VerifyingKey.universaKey: Unicrypto.PublicKey get() = (this as PublicKeyImpl).key
val SigningKey.universaKey: Unicrypto.PrivateKey get() = (this as PrivateKeyImpl).key