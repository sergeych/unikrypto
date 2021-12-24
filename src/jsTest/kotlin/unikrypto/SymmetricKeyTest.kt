package net.sergeych.unikrypto

import kotlinx.coroutines.await
import org.khronos.webgl.Uint8Array
import runTest
import kotlin.js.Promise
import kotlin.test.*

class SymmetricKeyTest {
    @Test
    fun testSymmetricKey() {
        return runTest {
            val k: Unicrypto.SymmetricKey = Unicrypto.SymmetricKey(undefined)
            val c = k.etaEncrypt("Helluva".encodeToByteArray())
            println("${c}--")
            println("${c.await()}--")
        }
    }
}