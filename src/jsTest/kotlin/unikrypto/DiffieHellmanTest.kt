import net.sergeych.mp_tools.decodeBase64
import net.sergeych.mp_tools.encodeToBase64
import net.sergeych.unikrypto.Unicrypto
import net.sergeych.unikrypto.digest
import net.sergeych.unikrypto.encodeToHex
import net.sergeych.unikrypto.toByteArray
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DiffieHellmanJsTest {
    @Test
    fun testInternal() {
        return runTest {
            val alice = DiffieHellman()
            val bob = DiffieHellman()

            alice.init()
            bob.proceed(alice.getExchange())
            alice.finalize(bob.getExchange())

            val key = bob.key?.encodeToBase64()
            assertTrue((key?.length ?: 0) > 0)
            assertEquals(bob.key?.encodeToBase64(),  alice.key?.encodeToBase64())
        }
    }

    @Test
    fun testJsInit() {
        return runTest {
            val p = "AKXjwFVAZhj2yVryCFffL0gyfDIrcLo+epNaNSlH3YQC9v9OP5AV5GOxHmbgwFdMh2dxOhzqWLK9mD/iCVG5FE8="
            val g = "GsOUYeuiSL3ztbHhu6bi4RHTWnptdnFg2QFV3lL85nEQ3OZRhpWQi52hzu1DnEYWp/RvbGd9NwBzdMHODTrG+Q=="
            val pub = "V/dOLgykaUNQUXzlq0ymBEL7US/sIXcBV0SWl1eIJz3RGD2uN1C/Ru/3EIPCyIJsmg/c7A1rK4YJD0yXvX42+g=="
            val priv = "B5krZq97U2QvmZ9R00fjkH71FVoZkjB/7rEHi1/HLoZRhK+eaz8oNcpVRSxWGIOKgyuD9X0oYgImEf6jWWlo+w=="

            val exchange = DHExchange(pub.decodeBase64(), p.decodeBase64(), g.decodeBase64())
            val alice = DiffieHellman()
            alice.initTest(exchange, priv.decodeBase64())

            val bobPublicKey = "WyAfYODQQCqtFG1sy3+PZB2CsDtYf1u7VUf5bRRtb8mLvuSmZDKU8gKqkY8NHVe2Z29zH+e0IUVWE7tvUHgRbA=="
            val exchangeFromBob = DHExchange(bobPublicKey.decodeBase64(), p.decodeBase64(), g.decodeBase64())
            alice.finalize(exchangeFromBob)

            assertTrue(alice.key!!.encodeToBase64() == "UC8DsF26bmB5tNKpQ3PTxEEwt/meUAYaOhnaQomh63oepluMEdNfAAPtmRae0txtlU8U/fOyuRqeNAJknx6Y0Q==")
        }
    }

//    @Test
//    fun testJavaInit() {
//        return runTest {
//            assertTrue { false }
//        }
//    }
}