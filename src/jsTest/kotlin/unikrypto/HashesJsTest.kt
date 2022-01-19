package net.sergeych.unikrypto

import runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@Suppress("unused")
class HashTestvector(val algorithm: HashAlgorithm, val source: String, resultHex: String) {
    val hex = resultHex.replace(" ", "")
}

val vectors = listOf(
    HashTestvector(HashAlgorithm.SHA256, "abc", "ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad")
)

class HashesJsTest {
    @Test
    fun testSha256() {
        return runTest {
            val src = "abc".encodeToByteArray()
            val hash = Unicrypto.SHA.getDigestSync("sha256", src).toByteArray()
            assertEquals(vectors[0].hex, hash.encodeToHex())
            assertEquals(vectors[0].hex, HashAlgorithm.SHA256.digest(src).encodeToHex())
        }
    }

    @Test
    fun pbkdf2Test() {
        return runTest {
            val password = "foobar"
            val (k1, k2) = Passwords.deriveKeys(password, 2, 10000)
            println(k1.id)
            println(k2.id)
            assertTrue { k1.id != k2.id }
            println(k1.keyBytes)
            println(k2.keyBytes)
            assertFalse { k1.keyBytes contentEquals k2.keyBytes }
        }
    }
}