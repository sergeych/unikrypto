/**
 * BinaryKV storage that uses MapDB tile backend, will work on most desktops.
 * see [boss-serialization-mp](https://github.com/sergeych/boss-serialization-mp)
 *
 *
 * On the web targets, there is
 * `BrowserBinaryStorage` already included in [boss-serializaion-mp]
 *
 *
 *
 */

// this one needs mapdb dependency, something like
// implementation("org.mapdb:mapdb:3.0.8")

package net.sergeych.common

import net.sergeych.boss_serialization_mp.KVBinaryStorage
import net.sergeych.mp_logger.LogTag
import net.sergeych.mp_logger.debug
import org.mapdb.DB
import org.mapdb.DBMaker
import org.mapdb.Serializer
import java.util.concurrent.ConcurrentMap

class MapdbBinaryKVStorage(dbFileName: String): LogTag("MDBST"), KVBinaryStorage {

    private val db: DB
    private val map: ConcurrentMap<String, ByteArray>

    init {
        debug { "initializing mapdb binary storage"}
        db = DBMaker.fileDB(dbFileName)
            .fileMmapEnableIfSupported()
            .closeOnJvmShutdown()
            .transactionEnable()
            .make()
        map = db.hashMap("kvBinaryStorage", Serializer.STRING, Serializer.BYTE_ARRAY)
            .createOrOpen()
    }

    override val keys: Set<String>
        get() = map.keys

    override fun get(key: String): ByteArray? = map[key]

    override fun remove(key: String): ByteArray? = map.remove(key)

    override fun set(key: String, value: ByteArray) {
        map[key] = value
    }
}
