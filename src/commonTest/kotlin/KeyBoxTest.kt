package net.sergeych.unikrypto

import runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class KeyboxTest {
    @Test
    fun testMapsObPlatofrm() {
        return runTest {
            val a = byteArrayOf(1,2,3)
            val b = byteArrayOf(1,2,3)
            val c = byteArrayOf(4,5,6)

            assertFalse { a == b }
            assertTrue { a contentEquals  b }

            val m = mutableMapOf<ByteArray,String>()
            m[a] = "foo"
            m[c] = "bar"
            assertEquals("foo", m[a])
            assertEquals("bar", m[c])
            println("most interesting:")
            assertEquals("foo", m[b])

        }
    }

}