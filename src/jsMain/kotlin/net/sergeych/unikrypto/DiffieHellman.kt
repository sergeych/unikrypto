import net.sergeych.mp_tools.decodeBase64
import net.sergeych.mp_tools.encodeToBase64
import net.sergeych.unikrypto.Unicrypto

class DiffieHellman: DiffieHellmanAbstract() {
    var df: Unicrypto.DiffieHellman? = null
    var public: String? = null
    override var key: ByteArray? = null

    override fun init() {
        df = Unicrypto.DiffieHellman.generate(DH_PRIME_SIZE)
        public = df?.generateKeys()
    }

    fun initTest(ex: DHExchange, priv: ByteArray) {
        df = Unicrypto.DiffieHellman(ex.p.encodeToBase64(), ex.g.encodeToBase64())
        public = df?.generateKeys()
        df?.setPublicKey(ex.pub.encodeToBase64())
        df?.setPrivateKey(priv.encodeToBase64())
    }

    override fun getExchange(): DHExchange {
        val pub = public?.decodeBase64() ?: throw Exception("DH is not initialized")
        val prime = df?.prime?.decodeBase64() ?: throw Exception("DH is not initialized")
        val generator = df?.generator?.decodeBase64() ?: throw Exception("DH is not initialized")

        return DHExchange(pub, prime, generator)
    }

    override fun proceed(exchange: DHExchange) {
        df = Unicrypto.DiffieHellman(exchange.p.encodeToBase64(), exchange.g.encodeToBase64())
        public = df?.generateKeys()
        key = df?.computeSecret(exchange.pub.encodeToBase64())?.decodeBase64()
    }

    override fun finalize(exchange: DHExchange) {
        key = df?.computeSecret(exchange.pub.encodeToBase64())?.decodeBase64()
    }
}