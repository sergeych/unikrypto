package net.sergeych.unikrypto

import runTest
import kotlin.experimental.xor
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AsymmetricKeyJsTest {
    @Test
    fun testAssymmetricKey() {
        return runTest {
            val src = "Helluva".encodeToByteArray()
//            val k = Unicrypto.PrivateKey.generate(PrivateKeyParams(2048)).await()
            val x =
                "JgAcAQABvIDL1TsAhGRNgTvw5NW0CUBbfuvfs1AbxQ4lqdfYDIWuqu4yUINpVPFuW2J1IYYEUp536maBjM6753gWoysuVKhqLPwyZK0CTD7QK44dL0HTtTVuhri465PlUtdCg1RFoAMsUovumrAvahMutKra31aFt3eMj3D7K51pId6MyA8Ei7yAu3HtALLUDCQGX3AY7/z74dPNSgATyVgYiq0IJfmb0uspPmHtx1GA8S67xvH6L7wp79Prd1DJ2E8ZLKgNpFj/WlSN+dNGWEN0GVN7oxNnEtjxTHUJY0WRzvw7wJuEDfjQYBn+qcWBboRytJ6xkGNlp992FwQJuMOTOSi0rIRmTmE="
                    .decodeBase64()
            val k = Unicrypto.PrivateKey.unpackSync(x)

            println("\n>> $k")
            val s = k.signSync(src, SigningOptions()).toByteArray()
            println("\nnsig: $s")
            val pubk = k.publicKey
            println("\npub: ${pubk}")
            assertTrue { pubk.verifySync(src, s, SigningOptions()) }
            val updated = src.toTypedArray().toByteArray()
            updated[2] = updated[2] xor 0x17
            assertFalse { src contentEquals updated }
            assertFalse { pubk.verifySync(updated, s, SigningOptions()) }

            val i1 = k.publicKey.longAddress
            val i2 = k.publicKey.shortAddress
            println("\n\n> $i1")
//            val i2 = k.shortAddress
//
            assertTrue { i1.isMatchingKey(k) }
            assertTrue { i2.isMatchingKey(k) }
        }
    }


}