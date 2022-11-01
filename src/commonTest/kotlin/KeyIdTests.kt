import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import net.sergeych.boss_serialization_mp.BossEncoder
import net.sergeych.boss_serialization_mp.decodeBoss
import net.sergeych.mp_tools.decodeBase64
import net.sergeych.mptools.encodeToHex
import net.sergeych.mptools.toDump
import net.sergeych.unikrypto.*
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class KeyIdTests {

    @OptIn(ExperimentalSerializationApi::class)
    @Test
    fun testPasswordIdSerialization() {
            val id1: KeyIdentity = PasswordId(
                Random.nextBytes(32),
                HashAlgorithm.SHA3_256,
                32,
                0,
                0,
                64,
                Random.nextBytes(16)
            )
            println("\n\n"+BossEncoder.encodeToStruct(id1).toString())
            println("\n\n"+BossEncoder.encode(id1).toDump())
            val id2: KeyIdentity = BossEncoder.encode(id1).decodeBoss()
            println(id2)
            assertTrue { id1 == id2}
    }

    @OptIn(ExperimentalSerializationApi::class)
    @Test
    fun testAddressKeyIdSerialization() = runTest {
        val password = "ihulfwer7"
        val testPackedKey = """
            Hhi8FxgFELggAMhAQg9keZWgPOim6zj7UymnxDoBatTkcmnfXdex7NtZOyCeqqGA0gpL8KxKFWvYCG77
            wBXO/eQmdJ3KqfYZ/ex2021VXmyOYB+345wD65Kq7003UYYe+Zpt+oqf8QlXbJZAMZtWzC5KL/S7/CLN
            YaO/IY8R4kZc03jFxrQCkDRB7GW8Bql5kfi8CU+pYNmcq2C5kmU3rytzxSD5S7b66ETMzOHBxmyBilCf
            N6hbAC9IWlR5OC76lVV+QAwcDy4E+AkTq3JBpb4FKLi4snSTPiMrXvaScYKLCnz1RxnOxH7s9Onihrj/
            MBT/l3ACha/f2dqk/2QCBElNdR3H2Hx85IQoyoav2wmLmcTRV0K1NsArUq7p2O6iTB3zzKDpCyXD+R/d
            VqxgyXWlPcZBL0UomES8x5PbQ1obzVoJVySFtkwu4oya4Kfd1VOoPuZQCgE=
        """.trimIndent().decodeBase64()
        val key = AsymmetricKeys.decryptPrivateKey(testPackedKey, password)
        val x = BossEncoder.encode(key.id).decodeBoss<KeyIdentity>()
        assertEquals(key.id, x)
    }
    @Test
    fun testKeyIdUnpacking() = runTest {
        val key = AsymmetricKeys.generate(2048)
        println(1)

        // TODO: check pack/unpack key address as string and binary!
        val packed = key.id.id
        val unpacked = AsymmetricKeys.unpackKeyId(packed)
        println(2)
        assertEquals(key.id, unpacked)
        val unpacked2 = AsymmetricKeys.unpackKeyId(key.id.asString)
        println(3)
        assertEquals(key.id, unpacked2)
    }

    @Serializable
    class TBytes3(val data: ByteArray)

    @Test
    fun toHex2() {
        val x: Byte = -1
        assertEquals("FF", x.encodeToHex())
        val c = byteArrayOf(-62,43,111,-99,-120,46,12,-72,14,11,95,105,124,-1,-50,-8,-71,-65,-12,-120,116,122,30,66,40,71,-20,80,93,53,-76,-19)
        assertEquals("{data=|C2 2B 6F 9D 88 2E 0C…(32)|}", BossEncoder.encodeToStruct(TBytes3(c)).toString())
    }

}