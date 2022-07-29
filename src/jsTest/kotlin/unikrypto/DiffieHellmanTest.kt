package net.sergeych.unikrypto

import net.sergeych.mp_tools.decodeBase64
import net.sergeych.mp_tools.encodeToBase64
import runTest
import kotlin.test.Test
import kotlin.test.assertTrue

class DiffieHellmanJsTest {
    @Test
    fun testInternal() = runTest {
        val alice = DiffieHellman()
        val bob = DiffieHellman()

        alice.init()
        bob.proceed(alice.getExchange())
        alice.finalize(bob.getExchange())

        assertTrue(bob.key != null && bob.key?.encodeToBase64() == alice.key?.encodeToBase64())
    }


    @Test
    fun testJsInit() = runTest {
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

    @Test
    fun testJavaInit() = runTest {
        val p = "9y3rcEfjlXgRx/AaaGyBrnfkju534WCODIesw0wLJI5oAYheahWR8zyJJ1cfrflK/DgRFaPSBlrZl8x87WuBow=="
        val g = "Ag=="
        val alicePublic = "bbWuZPKEaCdfXjaKfnCjGSABI9s4lFhYK4TFPgAgy9W9MBCLF9FYNnkCWxGA71vX9lCXucVrYTPUEXRcXkgjvg=="

        val bobPublic = "AKe8H4p8DYDpcTUHuzteJCX0xc/nxTRSYCzvD/n7p7rvMmwW6CutzEJImi6DmCN1JH96yfVAp9R9l/XH2cLOmqk="
        val bobPrivate = "ALd9oYAwrsx+kg6+Dc72iBtWUJgZV/Sk14LmI3QAmgJQnDMFvisEG9tU+0hr1vY+3lXRRY8I1ZHiX8Emmew7xz4="

        val bob = DiffieHellman()

        val exchangeFromAlice = DHExchange(alicePublic.decodeBase64(), p.decodeBase64(), g.decodeBase64())
        bob.proceedTest(exchangeFromAlice, bobPublic.decodeBase64(), bobPrivate.decodeBase64())
        assertTrue(bob.key!!.encodeToBase64() == "K9vzuRm1ZKaQ8u8yO9nKBkVkDPLkatp7GqsKTcjoWTQwXqSk6vYG0YJqXquLMcW9X1jPBZFSf3+629Hg0ggz7g==")
    }
}