import net.sergeych.mp_tools.decodeBase64
import net.sergeych.mp_tools.encodeToBase64
import net.sergeych.unikrypto.AsymmetricKeys
import net.sergeych.unikrypto.KeyAddress
import net.sergeych.unikrypto.PrivateKey
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

            println(k.packed.encodeToBase64())
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

    @Test
    fun unpackWithPassword() = runTest {
        val password = "ihulfwer7"
        val testPackedKey = """
            Hhi8FxgFELggAMhAQg9keZWgPOim6zj7UymnxDoBatTkcmnfXdex7NtZOyCeqqGA0gpL8KxKFWvYCG77
            wBXO/eQmdJ3KqfYZ/ex2021VXmyOYB+345wD65Kq7003UYYe+Zpt+oqf8QlXbJZAMZtWzC5KL/S7/CLN
            YaO/IY8R4kZc03jFxrQCkDRB7GW8Bql5kfi8CU+pYNmcq2C5kmU3rytzxSD5S7b66ETMzOHBxmyBilCf
            N6hbAC9IWlR5OC76lVV+QAwcDy4E+AkTq3JBpb4FKLi4snSTPiMrXvaScYKLCnz1RxnOxH7s9Onihrj/
            MBT/l3ACha/f2dqk/2QCBElNdR3H2Hx85IQoyoav2wmLmcTRV0K1NsArUq7p2O6iTB3zzKDpCyXD+R/d
            VqxgyXWlPcZBL0UomES8x5PbQ1obzVoJVySFtkwu4oya4Kfd1VOoPuZQCgE=
        """.trimIndent().decodeBase64()
        val expectedLongAddress = "JvpE8A4Niixqu9E58UxhYwPtBVfKHzX1bRaS5zCtqrjedtv364Th9ZX5EdTi7tmpHJ69Jp6S"
        val key = AsymmetricKeys.decryptPrivateKey(testPackedKey, password)

        assertEquals(expectedLongAddress, key.id.toString())
        assertTrue(KeyAddress.of(expectedLongAddress).matches(key) )

        val psw = "foobarbuzz"
        val k2 = AsymmetricKeys.decryptPrivateKey(key.packWithPassword(psw), psw)
        assertEquals(expectedLongAddress, k2.id.asString)
    }
}

