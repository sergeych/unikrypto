package net.sergeych.unikrypto

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.sergeych.boss_serialization_mp.BossEncoder
import net.sergeych.boss_serialization_mp.decodeBoss
import net.sergeych.mp_tools.decodeBase64Compact
import net.sergeych.mp_tools.encodeToBase64Compact
import net.sergeych.mptools.toDump
import org.junit.jupiter.api.Test

import org.junit.jupiter.api.Assertions.*
import runTest
import kotlin.random.Random
import kotlin.test.assertIs

internal class String_toolsKtTest {

    @Test
    fun decodeBase64Compact() {
        for(x in 1..34) {
            val a = Random.Default.nextBytes(x)
            val z = a.encodeToBase64Compact()
            assertArrayEquals(a, z.decodeBase64Compact())
        }
    }

    @Test
    fun bytesTestIdentities() {
        val x = BytesId(Random.nextBytes(32))
        val y = BytesId(Random.nextBytes(32))
        assertTrue { y != x }
        val z = BytesId(x.id)
        assertTrue( x == z)
        assertTrue( z == x)
        val t = BytesId.fromString(y.asString)
        assertTrue { y.asString == t.asString }
        assertTrue { y == t }
        assertTrue { t == y }
    }

    @Test
    fun serializeId() {
        val x = SymmetricKeys.random()
        val i: KeyIdentity = PasswordId(
            x.id.id,
            HashAlgorithm.SHA3_256,
            1000,
            32,
            0,
            64,
            Random.nextBytes(7)
        )
        println(i)
        println(Json.encodeToString(i))
        runTest {
            println(Json.encodeToString(i).length)
            val b = BossEncoder.encode(i)
            println(b.size)
            println(b.toDump())
            val x1 = b.decodeBoss<KeyIdentity>()
            assertIs<PasswordId>(x1)
            x1 as PasswordId
            kotlin.test.assertEquals(1000,x1.rounds)
            kotlin.test.assertEquals(HashAlgorithm.SHA3_256,x1.hashAlgorithm)
        }
    }
}