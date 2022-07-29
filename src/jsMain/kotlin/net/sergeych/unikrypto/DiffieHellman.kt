package net.sergeych.unikrypto

import net.sergeych.mp_tools.decodeBase64
import net.sergeych.mp_tools.encodeToBase64

actual class DiffieHellman {
    var df: Unicrypto.DiffieHellman? = null
    var public: ByteArray? = null
    actual var key: ByteArray? = null

    actual fun init() {
        df = Unicrypto.DiffieHellman.generate(DH_PRIME_SIZE)
        df?.generateKeys()
        public = df?.getPublicKey()?.decodeBase64()
    }

    fun initTest(ex: DHExchange, priv: ByteArray) {
        df = Unicrypto.DiffieHellman(ex.p.encodeToBase64(), ex.g.encodeToBase64())
        df?.setPublicKey(ex.pub.encodeToBase64())
        df?.setPrivateKey(priv.encodeToBase64())
    }

    actual fun getExchange(): DHExchange {
        println(public)
        val pub = public ?: throw Exception("DH is not initialized")
        val prime = df?.prime?.decodeBase64() ?: throw Exception("DH is not initialized")
        val generator = df?.generator?.decodeBase64() ?: throw Exception("DH is not initialized")

        return DHExchange(pub, prime, generator)
    }

    actual fun proceed(exchange: DHExchange) {
        df = Unicrypto.DiffieHellman(exchange.p.encodeToBase64(), exchange.g.encodeToBase64())
        df?.generateKeys()
        public = df?.getPublicKey()?.decodeBase64()
        key = df?.computeSecret(exchange.pub.encodeToBase64())?.decodeBase64()
    }

    fun proceedTest(ex: DHExchange, ownerPub: ByteArray, ownerPriv: ByteArray) {
        df = Unicrypto.DiffieHellman(ex.p.encodeToBase64(), ex.g.encodeToBase64())
        df?.setPublicKey(ownerPub.encodeToBase64())
        df?.setPrivateKey(ownerPriv.encodeToBase64())
        key = df?.computeSecret(ex.pub.encodeToBase64())?.decodeBase64()
    }

    actual fun finalize(exchange: DHExchange) {
        key = df?.computeSecret(exchange.pub.encodeToBase64())?.decodeBase64()
    }
}