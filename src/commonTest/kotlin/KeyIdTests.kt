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
        return runTest {
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
    }


        @Test
    fun testPasswordIds() {
        return runTest {
            val password = "foobar"
            val data = "fucked up beyond all recognition".encodeToByteArray()
            val (k1, k2) = Passwords.deriveKeys(password,2, 10000)
            assertEquals(32*3, (k1.id as PasswordId).generatedLength)
            assertTrue { k1.id != k2.id }
//            println(k1.keyBytes)
//            println(k2.keyBytes)
            assertFalse { k1.keyBytes contentEquals  k2.keyBytes }

            val x1 = k1.etaEncrypt(data)
            val x2 = k2.etaEncrypt(data)
            assertTrue { k1.etaDecrypt(x1) contentEquals data}
            assertTrue { k2.etaDecrypt(x2) contentEquals data}
            assertFails { k1.etaDecrypt(x2) }

            val kx2 = (k2.id as PasswordId).deriveKey(password)
            val kx1 = (k1.id as PasswordId).deriveKey(password)
            assertEquals(k2.id, kx2.id)
            assertEquals(k1.id, kx1.id)
            assertTrue { kx1.etaDecrypt(x1) contentEquals data}
            assertTrue { kx2.etaDecrypt(x2) contentEquals data}
            assertFails { kx1.etaDecrypt(x2) }

            val ki1 = BossEncoder.encode(k1.id).decodeBoss<KeyIdentity>()

//            println("\n\n K1: ${k1}")
//            println("\n\n   : ${k1.id.id} ${k1.id.id is ByteArray}")
//            println("\n\n   : ${ki1.id} ${ki1.id is ByteArray}")
//            val x = k1.id as PasswordId
//            val y = ki1 as PasswordId
//            println("\n\n   : ${x.keyLength} ${y.keyLength}")
//            println("\n\n   : ${x.keyOffset} ${y.keyOffset}")
//            println("\n\n   : ${x.keyIdAlgorithm} ${y.keyIdAlgorithm}")
//            println("\n\n   : ${x.generatedLength} ${y.generatedLength}")
//            println("\n\n   : ${x.hashAlgorithm} ${y.hashAlgorithm}")
//            println("\n\n   : ${x.seed} ${y.seed}")
//            println("\n\n   = ${x == y} ${y == x}")

            val e = BossEncoder.encode(k1.id)
//            println("\n\n${e.toDump()}")

            assertIs<PasswordId>(ki1)
            assertEquals(k1.id, ki1)
            val kr1 = ki1.deriveKey(password)
            assertTrue { kr1.etaDecrypt(x1) contentEquals data}
        }

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