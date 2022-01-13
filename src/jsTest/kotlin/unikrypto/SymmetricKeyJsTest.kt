package net.sergeych.unikrypto

import kotlinx.coroutines.await
import runTest
import kotlin.random.Random
import kotlin.test.*

class SymmetricKeyJsTest {
    @Test
    fun testSymmetricKey() {
        return runTest {
            val src = "Helluva".encodeToByteArray()
            val k: Unicrypto.SymmetricKey = Unicrypto.SymmetricKey()
            val c = k.etaEncrypt(src).await()
            println("\n\n---- ${c} ----")
            assertTrue { c.size > src.size }
            val d = k.etaDecrypt(c).await()
            assertContentEquals(src, d)
            println("\n\n${d.decodeToString()}\n")
            val k1 = Unicrypto.SymmetricKey(SymmetricKeyParams(k.pack()))
            val d1 = k1.etaDecrypt(c).await()
            assertContentEquals(src, d1)
            println("\n\n${d1.decodeToString()}\n")
//            println("\n\n${c.await().length}--\n\n")
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
            val k2 = SymmetricKeys.create(k.pack(), k.id.id)
            assertTrue { k2.id == k.id }
            assertEquals(src, k2.etaDecryptToString(k.etaEncrypt(src)))
        }
    }

    @Test
    fun decodeBase64Compact() {
        for(x in 1..34) {
            val a = Random.Default.nextBytes(x)
            val z = a.encodeToBase64Compact()
            assertContentEquals(a, z.decodeBase64Compact())
        }
    }

}