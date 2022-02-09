@file:Suppress("unused")

package net.sergeych.unikrypto

import kotlinx.coroutines.await
import org.khronos.webgl.Uint8Array

private val defaultOAEPOptions = OAEPOptions()

internal class PublicKeyImpl(val key: Unicrypto.PublicKey) : PublicKey() {
    override val id: KeyIdentity by lazy { BytesId(key.longAddress.asBinary.toByteArray()) }

    override val bitStrength: Int by lazy { key.getBitStrength() }

    override fun encryptBlock(plaintext: ByteArray): ByteArray =
        key.encryptSync(plaintext.toUint8Array(), defaultOAEPOptions).toByteArray()

    override val packed by lazy { key.packed.toByteArray() }

    override fun checkSignature(data: ByteArray, signature: ByteArray, hashAlgorithm: HashAlgorithm): Boolean
        = key.verifySync(data.toUint8Array(), signature.toUint8Array(), SigningOptions(pssHash = hashAlgorithm.toUniversa()))
}

internal class PrivateKeyImpl(val key: Unicrypto.PrivateKey) : PrivateKey() {

    override val id: KeyIdentity by lazy { BytesId(key.publicKey.longAddress.asBinary.toByteArray()) }

    override val publicKey: PublicKey by lazy { PublicKeyImpl(key.publicKey) }

    override fun decryptBlock(ciphertext: ByteArray): ByteArray =
        key.decryptSync(ciphertext.toUint8Array(), defaultOAEPOptions).toByteArray()

    override val packed: ByteArray by lazy { key.packSync() }

    override fun sign(data: ByteArray, hashAlgorithm: HashAlgorithm): ByteArray
        = key.signSync(data.toUint8Array(),SigningOptions(pssHash = hashAlgorithm.toUniversa())).toByteArray()
}

fun ByteArray.toUint8Array(): Uint8Array = Uint8Array(this.toTypedArray())

actual val AsymmetricKeys: AsymmetricKeysProvider = object : AsymmetricKeysProvider {
    override suspend fun generate(bitStrength: Int): PrivateKey {
        val pp = PrivateKeyParams(bitStrength)
//        console.log("\n\n-------->", pp)
//        console.log("\n\n")
//        throw Exception("the test")
        return PrivateKeyImpl(Unicrypto.PrivateKey.generate(pp).await())
    }

    override fun unpackPublic(data: ByteArray): PublicKey
        = PublicKeyImpl(Unicrypto.PublicKey.unpackSync(data.toUint8Array()))

    override fun unpackPrivate(data: ByteArray): PrivateKey
        = PrivateKeyImpl(Unicrypto.PrivateKey.unpackSync(data.toUint8Array()))
}

val VerifyingKey.universaKey: Unicrypto.PublicKey get() = (this as PublicKeyImpl).key
val SigningKey.universaKey: Unicrypto.PrivateKey get() = (this as PrivateKeyImpl).key