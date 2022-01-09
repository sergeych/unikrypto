package net.sergeych.unikrypto

import org.junit.jupiter.api.Test

import org.junit.jupiter.api.Assertions.*
import kotlin.random.Random

internal class String_toolsKtTest {

    @Test
    fun decodeBase64Compact() {
        for(x in 1..34) {
            val a = Random.Default.nextBytes(x)
            val x = a.toBase64Compact()
            assertArrayEquals(a, x.decodeBase64Compact())
        }
    }

    @Test
    fun bytesTestIdentities() {
        val x = BytesId(Random.nextBytes(32))
        val y = BytesId(Random.nextBytes(32))
        assertTrue { y != x }
        val z = BytesId(x.asByteArray)
        assertTrue( x.matches(z))
        assertTrue( z.matches(x))
        assertTrue( x == z)
        assertTrue( z == x)
        val t = BytesId.fromString(y.asString)
        assertTrue { y.asString == t.asString }
        assertTrue { y.matches(t) }
        assertTrue { y == t }
        assertTrue { t == y }
    }
}