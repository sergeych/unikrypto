import net.sergeych.boss_serialization_mp.BossEncoder
import net.sergeych.boss_serialization_mp.decodeBoss
import net.sergeych.unikrypto.*
import kotlin.test.*

class KeyIdTests {

    @Test
    fun testPasswordIds() {
        return runTest {
            val password = "foobar"
            val data = "fucked up beyond all recognition".encodeToByteArray()
            val (k1, k2) = Passwords.deriveKeys(password,2, 100000)
            println(k1.id)
            println(k2.id)
            assertTrue { k1.id != k2.id }
            println(k1.keyBytes)
            println(k2.keyBytes)
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
            assertIs<PasswordId>(ki1)
            assertEquals(k1.id, ki1)
            val kr1 = ki1.deriveKey(password)
            assertTrue { kr1.etaDecrypt(x1) contentEquals data}
        }
    }
}