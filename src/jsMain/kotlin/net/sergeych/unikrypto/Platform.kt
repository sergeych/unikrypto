package net.sergeych.unikrypto

import org.khronos.webgl.Uint8Array
import kotlin.js.Promise

@JsModule("unicrypto")
@JsNonModule
external class Unicrypto  {
    class SymmetricKeyParams(keyBytes: ByteArray);

    companion object {
        fun randomBytes(size: Int): ByteArray
    }

//    class AES(bits: ByteArray) {
//        fun encrypt(plaintext: ByteArray): ByteArray
//        fun decrypt(ciphertext: ByteArray): ByteArray
//    }

    class SymmetricKey(params: SymmetricKeyParams?) {
        suspend fun etaEncrypt(plaintext: ByteArray): Promise<Uint8Array>
    }

}