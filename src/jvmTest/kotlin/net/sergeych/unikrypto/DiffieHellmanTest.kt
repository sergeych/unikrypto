package net.sergeych.unikrypto

//import net.sergeych.mptools.BigInteger

import org.bouncycastle.crypto.params.DHPublicKeyParameters
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.math.BigInteger
import java.util.*

internal class DiffieHellmanTest {

    @Test
    fun DiffieHellmanCrossJSInit() {
        fun fromBase64(hex: String): BigInteger {
            val decoder = Base64.getDecoder()
            val decoded = decoder.decode(hex)
            println(decoded[0])
            return BigInteger(decoded)
//            println(Base64.decodeLines(hex)[0])
//            return BigInteger(Base64.decodeLines(hex))
        }

        val p0 = "g8RknFA/cki/l3JPXAIsXo6y0Yon71TrB0M7zG1PMrx1/8n5w+M62bEmxglD3L9lWtT8hdA8fifQlj6Ykk7LYw=="
        val g0 = "Ag=="
        val pub0 = "RejcBF9iRaZlWRtDsclfoT86VZlqvnK7a6N8ZJZsrVcOcZJ4JjLGxOoTRuQAfYtmzz0EwDeRcjeDSBatzgJKMg=="
//        val priv0 = "B5krZq97U2QvmZ9R00fjkH71FVoZkjB/7rEHi1/HLoZRhK+eaz8oNcpVRSxWGIOKgyuD9X0oYgImEf6jWWlo+w=="

        val ONE= BigInteger.valueOf(1)
        val TWO = BigInteger.valueOf(2)

        val limit = fromBase64(p0).subtract(TWO)
        println(fromBase64(pub0).compareTo(fromBase64(p0).subtract(TWO)))
        println(TWO.compareTo(ONE))
        println("====")
        println(fromBase64(p0))
        println(fromBase64(pub0))

        val alice = DiffieHellman()
        alice.proceed(p0, g0, pub0)

        println("alice public")
        println(alice.getPublicKey())
        println("alice secret")
        val encoder = Base64.getEncoder()
        val key64 = encoder.encodeToString(alice.key!!.toByteArray())
//        val key64 = Base64.encodeString(alice.key!!.toByteArray())
        println(key64)
        assertTrue(key64 == "UC8DsF26bmB5tNKpQ3PTxEEwt/meUAYaOhnaQomh63oepluMEdNfAAPtmRae0txtlU8U/fOyuRqeNAJknx6Y0Q==")
    }

//    @Test
//    fun DiffieHellmanCrossJavaInit() {
//        val p0 = "AKXjwFVAZhj2yVryCFffL0gyfDIrcLo+epNaNSlH3YQC9v9OP5AV5GOxHmbgwFdMh2dxOhzqWLK9mD/iCVG5FE8="
//        val g0 = "GsOUYeuiSL3ztbHhu6bi4RHTWnptdnFg2QFV3lL85nEQ3OZRhpWQi52hzu1DnEYWp/RvbGd9NwBzdMHODTrG+Q=="
//        val pub0 = "V/dOLgykaUNQUXzlq0ymBEL7US/sIXcBV0SWl1eIJz3RGD2uN1C/Ru/3EIPCyIJsmg/c7A1rK4YJD0yXvX42+g=="
//        val priv0 = "B5krZq97U2QvmZ9R00fjkH71FVoZkjB/7rEHi1/HLoZRhK+eaz8oNcpVRSxWGIOKgyuD9X0oYgImEf6jWWlo+w=="
//
//        val alice = DiffieHellman()
//        alice.initTest(p0, g0, pub0, priv0)
//
//        val bobPublicKey = "WyAfYODQQCqtFG1sy3+PZB2CsDtYf1u7VUf5bRRtb8mLvuSmZDKU8gKqkY8NHVe2Z29zH+e0IUVWE7tvUHgRbA=="
//        alice.finalize(bobPublicKey)
//        val key64 = Base64.encodeString(alice.key!!.toByteArray())
//        assertTrue(key64 == "UC8DsF26bmB5tNKpQ3PTxEEwt/meUAYaOhnaQomh63oepluMEdNfAAPtmRae0txtlU8U/fOyuRqeNAJknx6Y0Q==")
//    }

//    @Test
//    fun DiffieHellmanJava() {
//        val alice = DiffieHellman()
//        val bob = DiffieHellman()
//        alice.init()
//
//        val p = alice.getP()
//        val g = alice.getG()
//        val alicePublicKey = alice.getPublicKey()
//
//        bob.proceed(p, g, alicePublicKey)
//
//        val bobPublicKey = bob.getPublicKey()
//        alice.finalize(bobPublicKey)
//
////        println(bob.key?.toString(16))
//
//        assertTrue(bob.key?.toString(16) == alice.key?.toString(16))
//    }
}