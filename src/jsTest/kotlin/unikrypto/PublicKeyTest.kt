package net.sergeych.unikrypto

import kotlinx.coroutines.await
import runTest
import kotlin.experimental.xor
import kotlin.random.Random
import kotlin.test.*

class PublicKeyTest {
    @Test
    fun testAssymmetricKey() {
        return runTest {
            val src = "Helluva".encodeToByteArray()
            val k = Unicrypto.PrivateKey.generate(PrivateKeyParams(2048)).await()
            println("\n>> $k")
            val s = k.sign(src, SigningOptions()).await()
            println("\nnsig: $s")
            val pubk = k.publicKey
            println("\npub: ${pubk}")
            assertTrue { pubk.verify(src, s, SigningOptions()).await() }
            val updated = src.toTypedArray().toByteArray()
            updated[2] = updated[2] xor 0x17
            assertFalse { src contentEquals updated }
            assertFalse { pubk.verify(updated, s, SigningOptions()).await() }

            val i1 = k.publicKey.longAddress
            val i2 = k.publicKey.shortAddress
            println("\n\n> $i1")
//            val i2 = k.shortAddress
//
            assertTrue { i1.isMatchingKey(k) }
            assertTrue { i2.isMatchingKey(k) }
        }
    }

    @Test fun unpackKey() {
        return runTest {
            val x =
                "JgAcAQABvIDL1TsAhGRNgTvw5NW0CUBbfuvfs1AbxQ4lqdfYDIWuqu4yUINpVPFuW2J1IYYEUp536maBjM6753gWoysuVKhqLPwyZK0CTD7QK44dL0HTtTVuhri465PlUtdCg1RFoAMsUovumrAvahMutKra31aFt3eMj3D7K51pId6MyA8Ei7yAu3HtALLUDCQGX3AY7/z74dPNSgATyVgYiq0IJfmb0uspPmHtx1GA8S67xvH6L7wp79Prd1DJ2E8ZLKgNpFj/WlSN+dNGWEN0GVN7oxNnEtjxTHUJY0WRzvw7wJuEDfjQYBn+qcWBboRytJ6xkGNlp992FwQJuMOTOSi0rIRmTmE="
                    .decodeBase64()
            val k = AsymmetricKeys.unpackPrivate(x)
//            val k2 = AsymmetricKeys.unpackPublic(k.publicKey.pack())
//            println(k.id.asString)
//            println(k2.id.asString)
//            assertTrue { k2.id == k.id }
//            assertTrue { k2 == k.publicKey }
//            assertFalse { k2 == k }
        }
    }


}