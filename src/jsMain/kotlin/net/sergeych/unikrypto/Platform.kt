package net.sergeych.unikrypto

import org.khronos.webgl.Uint8Array
import kotlin.js.Promise

data class SymmetricKeyParams(val keyBytes: ByteArray)
data class PrivateKeyParams(val strength: Int)

data class SigningOptions(
    val salt: ByteArray?=null,
    val salLength: Int?=null,
    val mgf1Hash: String = "sha512",
    val pssHash: String = "sha3_384"
)

data class OAEPOptions(
    val seed: Uint8Array? = null, // optional, default none
    val mgf1Hash: String? = null,
    val oaepHash: String? = null
)

@JsModule("unicrypto")
@JsNonModule
external class Unicrypto  {

    companion object {
        fun randomBytes(size: Int): ByteArray
        fun encode64(data: ByteArray): String
        fun decode64(text: String): ByteArray
    }

    class SymmetricKey(params: SymmetricKeyParams = definedExternally) {
        suspend fun etaEncrypt(plaintext: ByteArray): Promise<ByteArray>
        suspend fun etaDecrypt(ciphertext: ByteArray): Promise<ByteArray>
        fun pack(): ByteArray
    }

    @Suppress("unused")
    class PublicKey {
        fun verify(message: ByteArray,signature: ByteArray,options: SigningOptions): Promise<Boolean>
        fun encrypt(plaintext: ByteArray,options: OAEPOptions): Promise<ByteArray>

        fun getBitStrength(): Int

        suspend fun pack(): Promise<ByteArray>

        val longAddress: KeyAddress
        val shortAddress: KeyAddress

        companion object {
            fun unpack(packed: ByteArray): Promise<PublicKey>
        }

    }

    class PrivateKey {

        fun sign(message: ByteArray, options: SigningOptions): Promise<ByteArray>
        fun decrypt(ciphertext: ByteArray,options: OAEPOptions): Promise<ByteArray>

        val publicKey: PublicKey

        suspend fun pack(): Promise<ByteArray>

        companion object {
            suspend fun generate(params: PrivateKeyParams): Promise<PrivateKey>
            suspend fun unpack(packed: dynamic,dummy: dynamic = definedExternally): Promise<PrivateKey>
        }
    }

    @Suppress("unused")
    class KeyAddress {

        val asBinary: ByteArray
        val asString: String

        fun isMatchingKey(k: PublicKey): Boolean
        fun isMatchingKey(k: PrivateKey): Boolean
    }


}