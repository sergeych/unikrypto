import net.sergeych.unikrypto.AsymmetricKeys
import net.sergeych.unikrypto.decodeBase64
import net.sergeych.unikrypto.toBase64
import kotlin.random.Random
import kotlin.test.*

class AssymmetricJvmTest {

    @Test
    fun etaEncryptSizes() {
        return runTest {
            val k = AsymmetricKeys.generate(2048)
            for (i in 1..300) {
                val src = Random.Default.nextBytes(i)
                val ct = k.publicKey.etaEncrypt(src)
                println("$i ${src.size} ${ct.size}")
                assertContentEquals(src, k.etaDecrypt(ct))
            }
        }
    }

    @Test fun signatures() {
        return runTest {
            val k = AsymmetricKeys.generate(2048)
            val text = "Hello1"
            val text2 = "Hello2"

            assertTrue { k.publicKey.checkSignature(text, k.sign(text)) }
            assertFalse { k.publicKey.checkSignature(text2, k.sign(text)) }

            println(k.pack().toBase64())
        }
    }

    @Test fun unpackKey() {
        return runTest {
            val x =
                "JgAcAQABvIDL1TsAhGRNgTvw5NW0CUBbfuvfs1AbxQ4lqdfYDIWuqu4yUINpVPFuW2J1IYYEUp536maBjM6753gWoysuVKhqLPwyZK0CTD7QK44dL0HTtTVuhri465PlUtdCg1RFoAMsUovumrAvahMutKra31aFt3eMj3D7K51pId6MyA8Ei7yAu3HtALLUDCQGX3AY7/z74dPNSgATyVgYiq0IJfmb0uspPmHtx1GA8S67xvH6L7wp79Prd1DJ2E8ZLKgNpFj/WlSN+dNGWEN0GVN7oxNnEtjxTHUJY0WRzvw7wJuEDfjQYBn+qcWBboRytJ6xkGNlp992FwQJuMOTOSi0rIRmTmE="
                    .decodeBase64()
            val k = AsymmetricKeys.unpackPrivate(x)
            val k2 = AsymmetricKeys.unpackPublic(k.publicKey.pack())
            println(k.id.asString)
            println(k2.id.asString)
            assertTrue { k2.id == k.id }
            assertTrue { k2 == k.publicKey }
            assertFalse { k2 == k }
        }
    }
}