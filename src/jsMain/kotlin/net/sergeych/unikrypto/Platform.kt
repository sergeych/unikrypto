package net.sergeych.unikrypto

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
        suspend fun etaEncrypt(plaintext: ByteArray): ByteArray
    }

}