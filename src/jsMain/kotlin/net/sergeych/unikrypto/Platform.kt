package net.sergeych.unikrypto

import org.khronos.webgl.Uint8Array
import kotlin.js.Promise

data class SymmetricKeyParams(val keyBytes: ByteArray)

@JsModule("unicrypto")
@JsNonModule
external class Unicrypto  {

    companion object {
        fun randomBytes(size: Int): ByteArray
    }

    class SymmetricKey(params: SymmetricKeyParams = definedExternally) {
        suspend fun etaEncrypt(plaintext: ByteArray): Promise<ByteArray>
        suspend fun etaDecrypt(ciphertext: ByteArray): Promise<ByteArray>
        fun pack(): ByteArray
    }

}