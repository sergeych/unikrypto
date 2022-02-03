package net.sergeych.unikrypto

import kotlinx.coroutines.await
import org.khronos.webgl.Uint8Array
import kotlin.js.Promise

@JsExport
data class SymmetricKeyParams(val keyBytes: Uint8Array)

@JsExport
data class PrivateKeyParams(val strength: Int)

@JsExport
data class SigningOptions(
    val salt: ByteArray? = null,
    val salLength: Int? = null,
    val mgf1Hash: String = "sha512",
    val pssHash: String = "sha3_384"
)

@JsExport
data class OAEPOptions(
    val seed: Uint8Array? = null, // optional, default none
    val mgf1Hash: String? = null,
    val oaepHash: String? = null
)

@JsExport
data class PBKDF2Params(
    val rounds: Int,
    val keyLength: Int,
    val password: String,
    val salt: Uint8Array
)

@JsModule("unicrypto")
@JsNonModule
external class Unicrypto {

    class SHA(hashAlgorithm: String) {

        fun putSync(data: Uint8Array)

        fun digest(): Uint8Array

        companion object {
            fun getDigestSync(name: String, source: ByteArray): Uint8Array
        }
    }

    companion object {
        fun randomBytes(size: Int): Uint8Array
        fun encode64(data: ByteArray): String
        fun decode64(text: String): Uint8Array
        fun pbkdf2(hashAlgoritmName: String, params: PBKDF2Params): Promise<Uint8Array>

        val unicryptoReady: Promise<Unit>
    }

    class SymmetricKey(params: SymmetricKeyParams = definedExternally) {
        fun etaEncryptSync(plaintext: Uint8Array): Uint8Array
        fun etaDecryptSync(ciphertext: Uint8Array): Uint8Array
        fun pack(): Uint8Array
    }

    @Suppress("unused")
    class PublicKey {
        fun verifySync(message: ByteArray, signature: ByteArray, options: SigningOptions): Boolean
        fun encryptSync(plaintext: ByteArray, options: OAEPOptions): Uint8Array

        fun getBitStrength(): Int

        val packed: Uint8Array

        val longAddress: KeyAddress
        val shortAddress: KeyAddress

        companion object {
            fun unpackSync(packed: ByteArray): PublicKey
        }

    }

    class PrivateKey {

        fun signSync(message: ByteArray, options: SigningOptions): Uint8Array
        fun decryptSync(ciphertext: ByteArray, options: OAEPOptions): Uint8Array

        val publicKey: PublicKey

        fun packSync(): ByteArray

        companion object {
            suspend fun generate(params: PrivateKeyParams): Promise<PrivateKey>
            fun unpackSync(packed: dynamic, dummy: dynamic = definedExternally): PrivateKey
        }
    }

    @Suppress("unused")
    class KeyAddress {

        val asBinary: Uint8Array
        val asString: String

        fun isMatchingKey(k: PublicKey): Boolean
        fun isMatchingKey(k: PrivateKey): Boolean
    }
}

@Suppress("unused")
suspend fun InitUnicrypto() {
    Unicrypto.unicryptoReady.await()
}

suspend fun <T>withUnicrypto(block: suspend ()->T): T {
    Unicrypto.unicryptoReady.await()
    return block()
}