import kotlinx.serialization.Serializable
import net.sergeych.boss_serialization_mp.BossEncoder
import net.sergeych.boss_serialization_mp.decodeBoss
import net.sergeych.mptools.toDump
import net.sergeych.mptools.toHex
import net.sergeych.unikrypto.HashAlgorithm
import net.sergeych.unikrypto.KeyIdentity
import net.sergeych.unikrypto.PasswordId
import net.sergeych.unikrypto.Passwords
import kotlin.random.Random
import kotlin.test.*

class KeyIdTests {

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

    @Serializable
    class TBytes3(val data: ByteArray)

    @Test
    fun toHex2() {
        val x: Byte = -1
        assertEquals("FF", x.toHex())
        val c = byteArrayOf(-62,43,111,-99,-120,46,12,-72,14,11,95,105,124,-1,-50,-8,-71,-65,-12,-120,116,122,30,66,40,71,-20,80,93,53,-76,-19)
        assertEquals("{data=|C2 2B 6F 9D 88 2E 0C…(32)|}", BossEncoder.encodeToStruct(TBytes3(c)).toString())
    }

}