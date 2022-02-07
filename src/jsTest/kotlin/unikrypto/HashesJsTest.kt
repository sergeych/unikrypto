package net.sergeych.unikrypto

import runTest
import kotlin.test.Test
import kotlin.test.assertEquals

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
    fun supportAllAlgorithms() = runTest {
        for( a in HashAlgorithm.values() ) {
            a.digest("hello")
//            console.log("${a.name}: ${a.digest("hello")}")
        }
    }
}