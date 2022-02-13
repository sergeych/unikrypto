package net.sergeych.unikrypto

import net.sergeych.boss_serialization_mp.KVBinaryStorage
import net.sergeych.boss_serialization_mp.MemoryKVBinaryStorage


interface GenericMutex {
    fun <T> withLock(block: () -> T): T
}

expect fun PlatformMutex(): GenericMutex

/**
 * Binady KV storage that supports changing backing storage on the fly. It is conventient for example when is is
 * needed to late encrypt a storage, for example, when the password is not immediately known.
 */
class BindableBinaryStorage(private var currentStorage: KVBinaryStorage = MemoryKVBinaryStorage()) : KVBinaryStorage {

    private val rebindingMutex = PlatformMutex()

    /**
     * Copies all data to other storage and use it from now on.
     * @param otherStorage where to store data now
     * @param clearOldOnDone if true, existing storage will be cleared after successful copying
     */
    fun rebindTo(otherStorage: KVBinaryStorage, clearOldOnDone: Boolean = false) {
        rebindingMutex.withLock {
            otherStorage.addAll(currentStorage)
            val oldStorage = currentStorage
            currentStorage = otherStorage
            if (clearOldOnDone) oldStorage.clear()
        }
    }

    override val keys: Set<String> get() = currentStorage.keys

    override fun get(key: String): ByteArray? = currentStorage.get(key)

    override fun remove(key: String): ByteArray? = currentStorage.remove(key)

    override fun set(key: String, value: ByteArray) {
        currentStorage.set(key, value)
    }
}
