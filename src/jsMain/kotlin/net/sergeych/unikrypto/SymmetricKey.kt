package net.sergeych.unikrypto

class SymmetricKeyImpl(id: ByteArray,bits: ByteArray): SymmetricKey(id) {

    private val key = Unicrypto.SymmetricKey(Unicrypto.SymmetricKeyParams(bits))

//    override fun etaEncrtypt(plaintext: ByteArray): ByteArray = key.encrypt(plaintext)
//    override fun etaDecrypt(ciphertext: ByteArray): ByteArray = key.decrypt(ciphertext)

    init {
        if( bits.size != 32) throw IllegalArgumentException("wrong bits size, needs 32 got ${bits.size}")
    }
}

actual val SymmetricKeys: SymmtricKeyProvider = object : SymmtricKeyProvider {
    override fun unpack(bits: ByteArray): SymmetricKey {
        TODO("Not yet implemented")
    }

    override fun random() = SymmetricKeyImpl(Unicrypto.randomBytes(32),Unicrypto.randomBytes(32))

}