import net.sergeych.boss_serialization_mp.KVStorage
import net.sergeych.boss_serialization_mp.MemoryKVBinaryStorage
import net.sergeych.mp_logger.Log
import net.sergeych.unikrypto.BindableBinaryStorage
import net.sergeych.unikrypto.EncryptedBinaryStorage
import net.sergeych.unikrypto.SymmetricKeys
import kotlin.test.*

class TestEncryptedStorage {

    @BeforeTest
    fun beforeAll() {
        println("---------------------------------------------")
        Log.defaultLevel = Log.Level.DEBUG
        Log.connectConsole()
    }

    @Test
    fun testBinaryStorage() = runTest {
        val source = MemoryKVBinaryStorage()
        val k1 = SymmetricKeys.random()
        val bs = EncryptedBinaryStorage(source,k1)
        bs["sss"] = "hello".encodeToByteArray()
        bs["foo"] = "foo".encodeToByteArray()
        println(bs.keys)
//        println(source.keys)
        assertEquals("hello",bs["sss"]!!.decodeToString())
        assertEquals("foo",bs["foo"]!!.decodeToString())

        val bs2 = EncryptedBinaryStorage(source, k1)
        assertEquals("hello",bs2["sss"]!!.decodeToString())
        assertEquals("foo",bs2["foo"]!!.decodeToString())

        val bs3 = EncryptedBinaryStorage(source, SymmetricKeys.random())
        assertEquals(0, bs3.keys.size)
        assertEquals(0, bs.keys.size)
    }

    @Test
    fun testStorage() = runTest {
        val source = MemoryKVBinaryStorage()
        val k1 = SymmetricKeys.random()
        val bs = EncryptedBinaryStorage(source,k1)
        val storage = KVStorage(bs)

        storage["foo"] = "bar"
        println(source.keys)
        assertEquals("bar", storage["foo"])
    }

    @Test
    fun testRebingingStorage() = runTest {
        val plain = MemoryKVBinaryStorage()
        val source = BindableBinaryStorage(plain)
        val storage = KVStorage(source)
        val k = SymmetricKeys.random()
        val encrypted = EncryptedBinaryStorage(MemoryKVBinaryStorage(),k)

        storage["foo"] = "bar"
        storage["bar"] = 42
        assertEquals(2, source.keys.size)
        assertEquals(2, plain.keys.size)
        assertEquals(0, encrypted.keys.size)

        source.rebindTo(encrypted, true)
        assertEquals(2, source.keys.size)
        assertEquals(2, storage.keys.size)
        assertEquals(2, encrypted.keys.size)
        assertEquals(0, plain.keys.size)

        assertEquals("bar", storage["foo"])
        assertEquals(42, storage["bar"])
    }
}