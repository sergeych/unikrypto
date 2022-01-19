import net.sergeych.unikrypto.AsymmetricKeys
import net.sergeych.unikrypto.PrivateKey
import net.sergeych.unikrypto.decodeBase64
import net.sergeych.unikrypto.toBase64
import kotlin.test.*

class CommonAssymetricKeyTests {

    fun testKey1(): PrivateKey {
        val x =
            "JgAcAQABvIDL1TsAhGRNgTvw5NW0CUBbfuvfs1AbxQ4lqdfYDIWuqu4yUINpVPFuW2J1IYYEUp536maBjM6753gWoysuVKhqLPwyZK0CTD7QK44dL0HTtTVuhri465PlUtdCg1RFoAMsUovumrAvahMutKra31aFt3eMj3D7K51pId6MyA8Ei7yAu3HtALLUDCQGX3AY7/z74dPNSgATyVgYiq0IJfmb0uspPmHtx1GA8S67xvH6L7wp79Prd1DJ2E8ZLKgNpFj/WlSN+dNGWEN0GVN7oxNnEtjxTHUJY0WRzvw7wJuEDfjQYBn+qcWBboRytJ6xkGNlp992FwQJuMOTOSi0rIRmTmE="
                .decodeBase64()
        return AsymmetricKeys.unpackPrivate(x)
    }

    @Test
    fun encryption() {
        return runTest {
            val k = testKey1()
            val src = "Hello 42"
            val packed = k.publicKey.etaEncrypt(src)
            val dec = k.etaDecryptToString(packed)
            println(dec)
            assertEquals(src, dec)
        }
    }

    @Test
    fun signatures() {
        return runTest {
            val k = testKey1()

            val text = "Hello1"
            val text2 = "Hello2"

            assertTrue { k.publicKey.checkSignature(text, k.sign(text)) }
            assertFalse { k.publicKey.checkSignature(text2, k.sign(text)) }

            println(k.packed.toBase64())
        }
    }

    @Test
    fun unpackKey() {
        return runTest {
            val x =
                "JgAcAQABvIDL1TsAhGRNgTvw5NW0CUBbfuvfs1AbxQ4lqdfYDIWuqu4yUINpVPFuW2J1IYYEUp536maBjM6753gWoysuVKhqLPwyZK0CTD7QK44dL0HTtTVuhri465PlUtdCg1RFoAMsUovumrAvahMutKra31aFt3eMj3D7K51pId6MyA8Ei7yAu3HtALLUDCQGX3AY7/z74dPNSgATyVgYiq0IJfmb0uspPmHtx1GA8S67xvH6L7wp79Prd1DJ2E8ZLKgNpFj/WlSN+dNGWEN0GVN7oxNnEtjxTHUJY0WRzvw7wJuEDfjQYBn+qcWBboRytJ6xkGNlp992FwQJuMOTOSi0rIRmTmE="
                    .decodeBase64()
            val k = AsymmetricKeys.unpackPrivate(x)
            println("\n\n -- $k == \n\n")
            println("\n\n -- ${k.id} == \n\n")
            val k2 = AsymmetricKeys.unpackPublic(k.publicKey.packed)
            println(k.id.asString)
            println(k2.id.asString)
            assertTrue { k2.id == k.id }
            assertTrue { k2.id == k.publicKey.id }
//            assertFalse { k2 == k }
        }
    }
}

