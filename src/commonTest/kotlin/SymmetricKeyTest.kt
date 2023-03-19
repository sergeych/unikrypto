package net.sergeych.unikrypto

import net.sergeych.boss_serialization_mp.BossEncoder
import net.sergeych.boss_serialization_mp.decodeBoss
import net.sergeych.mp_tools.decodeBase64Compact
import net.sergeych.mp_tools.encodeToBase64Compact
import runTest
import kotlin.random.Random
import kotlin.test.*

class SymmetricKeyTest {

    @Test
    fun testSymmetricProvider() {
        return runTest {
            val src = "Foo-42"
            val k = SymmetricKeys.random()
            println(k.id)
            val src2 = k.etaDecryptToString(k.etaEncrypt(src))
            assertEquals(src, src2)
            val k2 = SymmetricKeys.create(k.packed, k.id)
            assertTrue { k2.id == k.id }
            assertEquals(src, k2.etaDecryptToString(k.etaEncrypt(src)))
            val k3 = SymmetricKeys.create(k.packed)
            assertTrue { k3.id == k.id }
            assertEquals(src, k3.etaDecryptToString(k.etaEncrypt(src)))
            val oldKey = SymmetricKeys.create(k.keyBytes, BytesId(k.id.id))
            assertTrue { oldKey.id == k.id }
            assertEquals(src, oldKey.etaDecryptToString(k.etaEncrypt(src)))
//            println(BossEncoder.encode(k3).toDump())
//            println(BossEncoder.encode(oldKey).toDump())
            assertTrue { BossEncoder.encode(k3).size < BossEncoder.encode(oldKey).size }
        }
    }

    @Test
    fun decodeBase64Compact() {
        for (x in 1..34) {
            val a = Random.Default.nextBytes(x)
            val z = a.encodeToBase64Compact()
            assertContentEquals(a, z.decodeBase64Compact())
        }
    }

    @Test
    fun pbkdf2Test() {
        return runTest {
            val password = "foobar"
            val (k1, k2) = Passwords.deriveKeys(password, 2, 10000)
            println(k1.id)
            println(k2.id)
            assertTrue { k1.id != k2.id }
            println(k1.keyBytes)
            println(k2.keyBytes)
            assertFalse { k1.keyBytes contentEquals k2.keyBytes }
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

//            val e = BossEncoder.encode(k1.id)

            assertIs<PasswordId>(ki1)
            assertEquals(k1.id, ki1)
            val kr1 = ki1.deriveKey(password)
            assertTrue { kr1.etaDecrypt(x1) contentEquals data}
        }

    }

    @Test
    fun symmetricKeyEtaTest() = runTest {
        InitUnicrypto()
        val src = "Hello world"
        val sk1 = SymmetricKeys.random()

        val packed1 = sk1.etaEncrypt(src)
        val packed2 = sk1.etaEncrypt(src)

        assertFalse { packed1 contentEquals packed2 }
    }


}