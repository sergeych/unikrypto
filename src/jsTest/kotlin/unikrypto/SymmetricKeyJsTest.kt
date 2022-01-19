package net.sergeych.unikrypto

import runTest
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SymmetricKeyJsTest {
    @Test
    fun testSymmetricKey() {
        return runTest {
            val src = "Helluva".encodeToByteArray()
            val k: Unicrypto.SymmetricKey = Unicrypto.SymmetricKey()
            val c = k.etaEncryptSync(src.toUint8Array())
            println("\n\n---- ${c} ----")
            assertTrue { c.length > src.size }
            val d = k.etaDecryptSync(c.toByteArray().toUint8Array()).toByteArray()
            assertContentEquals(src, d)
            println("\n\n${d.decodeToString()}\n")
            val k1 = Unicrypto.SymmetricKey(SymmetricKeyParams(k.pack()))
            val d1 = k1.etaDecryptSync(c.toByteArray().toUint8Array()).toByteArray()
            assertContentEquals(src, d1)
            println("\n\n${d1.decodeToString()}\n")
        }
    }

    @Test
    fun testSymmetricKeyCreation() {
        return runTest {
            val k1 = Unicrypto.SymmetricKey(SymmetricKeyParams(Random.nextBytes(32).toUint8Array()))
            val src = "Helluva".encodeToByteArray()
            val e = k1.etaEncryptSync(src.toUint8Array())
            val d = k1.etaDecryptSync(e)
            assertContentEquals(src, d.toByteArray())
        }
    }

    @Test
    fun testSymmetricProvider() {
        return runTest {
            val src = "Foo-42"
            val k = SymmetricKeys.random()
            println(k.id)
            val src2 = k.etaDecryptToString(k.etaEncrypt(src))
            assertEquals(src, src2)
            val k2 = SymmetricKeys.create(k.packed, k.id)
            assertTrue { k2.id == k.id }
            assertEquals(src, k2.etaDecryptToString(k.etaEncrypt(src)))
        }
    }

    @Test
    fun decodeBase64Compact() {
        for (x in 1..34) {
            val a = Random.Default.nextBytes(x)
            val z = a.encodeToBase64Compact()
            assertContentEquals(a, z.decodeBase64Compact())
        }
    }

}