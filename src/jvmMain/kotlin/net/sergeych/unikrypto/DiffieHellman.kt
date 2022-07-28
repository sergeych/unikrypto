package net.sergeych.unikrypto

import net.sergeych.utils.Base64
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.agreement.DHBasicAgreement
import org.bouncycastle.crypto.generators.DHKeyPairGenerator
import org.bouncycastle.crypto.generators.DHParametersGenerator
import org.bouncycastle.crypto.params.DHKeyGenerationParameters
import org.bouncycastle.crypto.params.DHParameters
import org.bouncycastle.crypto.params.DHPrivateKeyParameters
import org.bouncycastle.crypto.params.DHPublicKeyParameters
import org.bouncycastle.jcajce.provider.symmetric.ARC4.Base
import java.math.BigInteger
import java.security.SecureRandom

private val CERTAINTY = 30
private val PRIME_SIZE = 512

private fun fromBase64(hex: String): BigInteger {
    return BigInteger(Base64.decodeLines(hex))
//    BigInteger(hex, 16)
}

class DiffieHellman {
    var pair: AsymmetricCipherKeyPair? = null
    var key: BigInteger? = null
    var params: DHParameters? = null

    private var agreement: DHBasicAgreement? = null

    private fun getParameter(param: BigInteger?): String {
        if (param == null) throw Exception("DH is not initialized")
        return Base64.encodeString(param.toByteArray())
    }

    fun getP(): String = getParameter(params?.p)
    fun getG(): String = getParameter(params?.g)
    fun getPublicKey(): String {
        val pub = pair?.public ?: throw Exception("DH is not initialized")
        return Base64.encodeString((pub as DHPublicKeyParameters).y.toByteArray())
    }

    fun getPrivateKey(): String {
        val priv = pair?.private ?: throw Exception("DH is not initialized")
        return Base64.encodeString((priv as DHPrivateKeyParameters).x.toByteArray())
    }

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

    fun init() {
        val generator = DHParametersGenerator()
        generator.init(PRIME_SIZE, CERTAINTY, SecureRandom())
        params = generator.generateParameters()
        pair = generatePair(params!!)


        println("P")
        println(getP())
        println("G")
        println(getG())
        println("PUB")
        println(getPublicKey())
        println("PRIV")
        println(getPrivateKey())

        agreement = generateAgreement()
    }

    fun initTest(p: String, g: String, pub: String, priv: String) {
        params = DHParameters(fromBase64(p), fromBase64(g))

        pair = AsymmetricCipherKeyPair(
            DHPublicKeyParameters(fromBase64(pub), params),
            DHPrivateKeyParameters(fromBase64(priv), params)
        )

        agreement = generateAgreement()
    }

    fun proceed(p: BigInteger, g: BigInteger, publicKey: BigInteger) {
        params = DHParameters(p, g)
        val pub = DHPublicKeyParameters(publicKey, params)
        pair = generatePair(params!!)
        agreement = generateAgreement()
        key = agreement?.calculateAgreement(pub)
    }

    fun proceed(pString: String, gString: String, publicString: String) {
        return proceed(fromBase64(pString), fromBase64(gString), fromBase64(publicString))
    }

    fun finalize(publicKey: BigInteger) {
        val pub = DHPublicKeyParameters(publicKey, params)
        key = agreement?.calculateAgreement(pub)
    }

    fun finalize(publicString: String) {
        return finalize(fromBase64(publicString))
    }
}