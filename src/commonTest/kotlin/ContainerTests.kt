@file:Suppress("unused")

import net.sergeych.boss_serialization_mp.BossEncoder
import net.sergeych.boss_serialization_mp.decodeBoss
import net.sergeych.bossk.Bossk
import net.sergeych.mp_tools.decodeBase64
import net.sergeych.mp_tools.indexOf
import net.sergeych.mptools.toDump
import net.sergeych.unikrypto.*
import kotlin.random.Random
import kotlin.test.*

class ContainerTests {

    fun testKey1(): PrivateKey {
        val x =
            "JgAcAQABvIDL1TsAhGRNgTvw5NW0CUBbfuvfs1AbxQ4lqdfYDIWuqu4yUINpVPFuW2J1IYYEUp536maBjM6753gWoysuVKhqLPwyZK0CTD7QK44dL0HTtTVuhri465PlUtdCg1RFoAMsUovumrAvahMutKra31aFt3eMj3D7K51pId6MyA8Ei7yAu3HtALLUDCQGX3AY7/z74dPNSgATyVgYiq0IJfmb0uspPmHtx1GA8S67xvH6L7wp79Prd1DJ2E8ZLKgNpFj/WlSN+dNGWEN0GVN7oxNnEtjxTHUJY0WRzvw7wJuEDfjQYBn+qcWBboRytJ6xkGNlp992FwQJuMOTOSi0rIRmTmE="
                .decodeBase64()
        return AsymmetricKeys.unpackPrivate(x)
    }

    @Test
    fun simple() = runTest {
        val src = "The fake vaccine kills"
        val sk1 = SymmetricKeys.random()

        val pc1 = Container.encrypt(src, sk1)
//        println(pc1.toDump())
//        println(Bossk.unpack<Map<String, Any>>(pc1))
        assertTrue { pc1.indexOf("single") > 0 }
        assertTrue { pc1.indexOf("single") < 10 }
        assertNotNull(Container.decrypt<String>(pc1, sk1))
//        println("\n\n Decrypted $r")
        assertEquals(src, Container.decrypt(pc1, sk1))
    }

    @Test
    fun updateSingle() {
        val src = "The fake vaccine kills"
        val src2 = "The fake vaccine kills2"
        val sk1 = SymmetricKeys.random()
        val sk2 = SymmetricKeys.random()

        val pc1 = Container.encrypt(src, sk1)
        println(pc1.toDump())
        assertNull(Container.decrypt<String>(pc1, sk2))
        val pc2 = Container.update(pc1, Keyring(sk1), src2)
        assertEquals(src2, Container.decrypt<String>(pc2!!, sk1))
        assertNull(Container.decrypt<String>(pc2, sk2))
    }

    @Test
    fun updateMulti() {
        val src = "The fake vaccine kills"
        val src2 = "The fake vaccine kills2"
        val sk1 = SymmetricKeys.random()
        val sk2 = SymmetricKeys.random()
        val sk3 = SymmetricKeys.random()
        val sk4 = SymmetricKeys.random()

        val pc1 = Container.encrypt(src, sk1, sk2, sk3)

        assertNull(Container.decrypt<String>(pc1, sk4))
        val pc2 = Container.update(pc1, Keyring(sk2), src2)!!
        assertEquals(src2, Container.decrypt<String>(pc2, sk1))
        assertEquals(src2, Container.decrypt<String>(pc2, sk2))
        assertEquals(src2, Container.decrypt<String>(pc2, sk3))
        assertEquals(null, Container.decrypt<String>(pc2, sk4))
    }


    @Test
    fun multi() = runTest {
        val src = "The fake vaccine kills"
        val sk1 = SymmetricKeys.random()
        val sk2 = SymmetricKeys.random()
        val sk3 = SymmetricKeys.random()
        val sk4 = SymmetricKeys.random()
        val sk5 = SymmetricKeys.random()

        val pc1 = Container.encrypt(src, sk1, sk2, sk3)
        println(pc1.toDump())
        assertNull(Container.decrypt<String>(pc1, sk4))
        assertNull(Container.decrypt<String>(pc1, sk5))
        assertEquals(src, Container.decrypt<String>(pc1, sk1))
        assertEquals(src, Container.decrypt<String>(pc1, sk3))
        assertEquals(src, Container.decrypt<String>(pc1, sk2))

        assertEquals(src, Container.decrypt<String>(pc1, Keyring(sk4, sk5, sk3)))
        assertEquals(src, Container.decrypt<String>(pc1, sk4, sk5, sk1, sk2))

        val kr2 = BossEncoder.encode(Keyring(sk4, sk5, sk1)).decodeBoss<Keyring>()
        assertEquals(src, Container.decrypt<String>(pc1, kr2))

        println(Bossk.unpack<Map<String, Any>>(pc1))
        assertEquals(src, Container.decrypt(pc1, sk1))
    }

    @Test
    fun keyIdsAsSet() {
        val ki1 = BytesId.random()
        val ki2 = BytesId.random()
        val ki3 = BytesId.random()

        val ki3_1 = BytesId(ki3.id.toTypedArray().toByteArray())

        val s = setOf(ki1, ki2, ki3)
        assertTrue { ki1 in s }
        assertTrue { ki2 in s }
        assertTrue { ki3 in s }
        assertTrue { ki3_1 in s }
    }

    @Test
    fun wrongContainerUnpack() {
        val src = "The fake vaccine kills"
        val sk1 = SymmetricKeys.random()
        val sk2 = SymmetricKeys.random()

        val pc1 = Container.encrypt(src, sk1)

        val pc2 = BossEncoder.encode(
            Container.Single(sk1.id, sk1.etaEncrypt(
                BossEncoder.encode(src))) as Container
        )


        assertEquals(src, Container.decrypt<String>(pc1, sk1))

        assertEquals(src, Container.decrypt<String>(pc2, sk1))

        // Faulure 1: Not a container
        assertThrows<Container.StructureError> {
            Container.decryptAsBytes(Random.Default.nextBytes(pc1.size))
        }
//        println(x)
        // Faulure 2: Container but wrong ciphertext
        val pc3 = BossEncoder.encode(
            Container.Single(sk1.id, sk2.etaEncrypt(
                BossEncoder.encode(src))) as Container
        )
        assertNull(
            Container.decryptAsBytes(pc3, sk1)
        )

    }

    @Test
    fun unpackWithSymmetricKeyWithWrongID() {
        val k1 = SymmetricKeys.random()
        val k2 = SymmetricKeys.random()
        val k3 = SymmetricKeys.random()
        val k1wrongId = SymmetricKeys.create(k1.keyBytes,BytesId.random())

        // Single:
        var c = Container.encrypt("hello, world", k1)
        assertEquals("hello, world", Container.decrypt(c,k1))
        assertEquals("hello, world", Container.decrypt(c,k1wrongId))

        // multi:
        c = Container.encrypt("hello, world", k1, k2, k3)
        assertEquals("hello, world", Container.decrypt(c,k1))
        assertEquals("hello, world", Container.decrypt(c,k2))
        assertEquals("hello, world", Container.decrypt(c,k3))
        assertEquals("hello, world", Container.decrypt(c,k1wrongId))
    }

}

