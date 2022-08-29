package net.sergeych.unikrypto

actual class DiffieHellman {
    var df: Unicrypto.DiffieHellman? = null
    var public: ByteArray? = null

    actual fun init() {
        df = Unicrypto.DiffieHellman.generate(DH_PRIME_SIZE)
        df?.generateKeys()
        public = df?.getPublicKey().toByteArray()
    }

    fun initTest(ex: DHExchange, priv: ByteArray) {
        df = Unicrypto.DiffieHellman(ex.p.toUint8Array(), ex.g.toUint8Array())
        df?.setPublicKey(ex.pub.toUint8Array())
        df?.setPrivateKey(priv.toUint8Array())
    }

    actual fun getExchange(): DHExchange {
        val pub = public ?: throw Exception("DH is not initialized")
        val prime = df?.prime?.toByteArray() ?: throw Exception("DH is not initialized")
        val generator = df?.generator?.toByteArray() ?: throw Exception("DH is not initialized")

        return DHExchange(pub, prime, generator)
    }

    actual fun proceed(exchange: DHExchange): ByteArray {
        val diffie = Unicrypto.DiffieHellman(exchange.p.toUint8Array(), exchange.g.toUint8Array())
        df = df ?: diffie
        diffie.generateKeys()
        public = diffie.getPublicKey().toByteArray()
        return diffie.computeSecret(exchange.pub.toUint8Array()).toByteArray()
    }

    fun proceedTest(ex: DHExchange, ownerPub: ByteArray, ownerPriv: ByteArray): ByteArray {
        val diffie = Unicrypto.DiffieHellman(ex.p.toUint8Array(), ex.g.toUint8Array())
        df = df ?: diffie
        diffie.setPublicKey(ownerPub.toUint8Array())
        diffie.setPrivateKey(ownerPriv.toUint8Array())
        return diffie.computeSecret(ex.pub.toUint8Array()).toByteArray()
    }

    actual fun finalize(exchange: DHExchange): ByteArray {
        val diffie = df ?: Unicrypto.DiffieHellman(exchange.p.toUint8Array(), exchange.g.toUint8Array())
        return diffie.computeSecret(exchange.pub.toUint8Array()).toByteArray()
    }
}