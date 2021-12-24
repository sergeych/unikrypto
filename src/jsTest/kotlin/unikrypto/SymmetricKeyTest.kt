package net.sergeych.unikrypto

import runTest
import kotlin.test.*

class SymmetricKeyTest {
    @Test
    fun testSymmetricKey() {
        println("bnefore")
        return runTest {
//        val a = Unicrypto.randomBytes(32)
//        val b = Unicrypto.randomBytes(32)
//        val k = SymmetricKeyImpl(a,b)
            val k: Unicrypto.SymmetricKey = Unicrypto.SymmetricKey(undefined)
            val c = k.etaEncrypt("Helluva".encodeToByteArray())
//        println("> ${k.canDecrypt}")
            println(c)
//        println(k.etaDecryptToString(c))
        }
    }
}