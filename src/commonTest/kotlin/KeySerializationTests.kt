@file:UseSerializers(IdentifiableKeySerializer::class)

import kotlinx.serialization.Serializable
import kotlinx.serialization.UseSerializers
import net.sergeych.boss_serialization.BossDecoder
import net.sergeych.boss_serialization_mp.BossEncoder
import net.sergeych.boss_serialization_mp.decodeBoss
import net.sergeych.mp_tools.decodeBase64
import net.sergeych.mptools.decodeHex
import net.sergeych.mptools.toDump
import net.sergeych.unikrypto.*
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class KeySerializationTests {

    @Serializable
    class TT1(
        @Serializable(with=IdentifiableKeySerializer::class)
        val key: IdentifiableKey
    )

//    @Test
//    fun testSymmKeyCreation() = runTest {
//        val s1 = "000102030405060708090a0b0c0d0e0f".decodeHex()
//        val s = s1 + s1
//        val k1 = SymmetricKeys.create(s, BytesId.random())
//        val k2 = SymmetricKeys.create(s, BytesId.random())
//        println("\n\n:: ${s.encodeToHex()}")
//        println("\n\n:: ${k1.packed.encodeToHex()}")
//        println("\n\n:: ${k2.packed.encodeToHex()}")
//    }

    @Test
    fun testPropertyKeySerialization() {
        val k = TT1(SymmetricKeys.random())
        val sk = BossEncoder.encodeToStruct(k)
        println(sk)
        val k2 = BossDecoder.decodeFrom<TT1>(sk)
        println(k2)
        assertEquals(k2.key.id, k.key.id)

        println("\n\n1: ${k.key.packed}")
        println("\n\n2: ${k2.key.packed}")

        assertContentEquals(k2.key.packed, k.key.packed)
//
//        val prk = testKey1()
//        var t = TT1(prk)
//        println(BossEncoder.encodeToStruct(t))
//        println(BossDecoder.decodeFrom<TT1>(BossEncoder.encodeToStruct(t)))
//        assertEquals(t.key.id, BossEncoder.encode(t).decodeBoss<TT1>().key.id)
//        t = TT1(prk.publicKey)
//        assertEquals(t.key.id, BossEncoder.encode(t).decodeBoss<TT1>().key.id)
    }

    @Test
    fun testKeyrinSerialization() {
        val sk1 = SymmetricKeys.random()
        val sk2 = SymmetricKeys.random()
        val sk3 = SymmetricKeys.random()
        val sk4 = SymmetricKeys.random()

        val r = Keyring(sk2, sk2, sk3)
        val x = BossEncoder.encode(r)
        println(x.toDump())
        val r1: Keyring = x.decodeBoss()
        assertEquals(r, r1)
    }


    fun testKey1(): PrivateKey {
        val x =
            "JgAcAQABvIDL1TsAhGRNgTvw5NW0CUBbfuvfs1AbxQ4lqdfYDIWuqu4yUINpVPFuW2J1IYYEUp536maBjM6753gWoysuVKhqLPwyZK0CTD7QK44dL0HTtTVuhri465PlUtdCg1RFoAMsUovumrAvahMutKra31aFt3eMj3D7K51pId6MyA8Ei7yAu3HtALLUDCQGX3AY7/z74dPNSgATyVgYiq0IJfmb0uspPmHtx1GA8S67xvH6L7wp79Prd1DJ2E8ZLKgNpFj/WlSN+dNGWEN0GVN7oxNnEtjxTHUJY0WRzvw7wJuEDfjQYBn+qcWBboRytJ6xkGNlp992FwQJuMOTOSi0rIRmTmE="
                .decodeBase64()
        return AsymmetricKeys.unpackPrivate(x)
    }

}