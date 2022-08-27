package net.sergeych.unikrypto

import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.agreement.DHBasicAgreement
import org.bouncycastle.crypto.generators.DHKeyPairGenerator
import org.bouncycastle.crypto.generators.DHParametersGenerator
import org.bouncycastle.crypto.params.DHKeyGenerationParameters
import org.bouncycastle.crypto.params.DHParameters
import org.bouncycastle.crypto.params.DHPrivateKeyParameters
import org.bouncycastle.crypto.params.DHPublicKeyParameters
import java.math.BigInteger
import java.security.SecureRandom

actual class DiffieHellman {
    var pair: AsymmetricCipherKeyPair? = null
    var params: DHParameters? = null

    private var agreement: DHBasicAgreement? = null
    private fun getParameter(param: BigInteger?): ByteArray {
        if (param == null) throw Exception("DH is not initialized")
        return param.toByteArray()
    }
    fun getP(): ByteArray = getParameter(params?.p)
    fun getG(): ByteArray = getParameter(params?.g)
    fun getPublicKey(): ByteArray {
        val pub = pair?.public ?: throw Exception("DH is not initialized")
        val y = (pub as DHPublicKeyParameters).y
        return y.toByteArray()
    }
    actual fun getExchange(): DHExchange = DHExchange(getPublicKey(), getP(), getG())
    private fun generatePair(params: DHParameters): AsymmetricCipherKeyPair {
        val keyGen = DHKeyPairGenerator()
        val DHKeyGenParams = DHKeyGenerationParameters(SecureRandom(), params)
        keyGen.init(DHKeyGenParams)
        val pair = keyGen.generateKeyPair()

        return pair
    }

    private fun generateAgreement(): DHBasicAgreement {
        val agreement = DHBasicAgreement()
        agreement.init(pair?.private)
        return agreement
    }

    actual fun init() {
        val generator = DHParametersGenerator()
        generator.init(DH_PRIME_SIZE, DH_CERTAINTY, SecureRandom())
        params = generator.generateParameters()
        pair = generatePair(params!!)

        agreement = generateAgreement()
    }

    fun initTest(ex: DHExchange, priv: ByteArray) {
        params = DHParameters(BigInteger(1, ex.p), BigInteger(1, ex.g))

        pair = AsymmetricCipherKeyPair(
            DHPublicKeyParameters(BigInteger(1, ex.pub), params),
            DHPrivateKeyParameters(BigInteger(1, priv), params)
        )

        agreement = generateAgreement()
    }
    actual fun proceed(exchange: DHExchange): ByteArray {
        params = DHParameters(BigInteger(1, exchange.p), BigInteger(1, exchange.g))
        val pub = DHPublicKeyParameters(BigInteger(1, exchange.pub), params)
        pair = generatePair(params!!)
        val agreement = generateAgreement()
        return agreement.calculateAgreement(pub).toByteArray()
    }

    fun proceedTest(exchange: DHExchange, ownerPub: ByteArray, ownerPriv: ByteArray): ByteArray {
        params = DHParameters(BigInteger(1, exchange.p), BigInteger(1, exchange.g))
        val pub = DHPublicKeyParameters(BigInteger(1, exchange.pub), params)

        pair = AsymmetricCipherKeyPair(
            DHPublicKeyParameters(BigInteger(1, ownerPub), params),
            DHPrivateKeyParameters(BigInteger(1, ownerPriv), params)
        )

        val agreement = generateAgreement()
        return agreement.calculateAgreement(pub).toByteArray()
    }

    actual fun finalize(exchange: DHExchange): ByteArray {
        val pub = DHPublicKeyParameters(BigInteger(exchange.pub), params)
        val agreement = generateAgreement()
        return agreement.calculateAgreement(pub).toByteArray()
    }
}