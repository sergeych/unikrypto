package net.sergeych.unikrypto

import kotlinx.serialization.Serializable
import net.sergeych.boss_serialization_mp.BossEncoder
import net.sergeych.boss_serialization_mp.KVBinaryStorage
import net.sergeych.boss_serialization_mp.decodeBoss
import net.sergeych.mp_logger.LogTag
import net.sergeych.mp_logger.debug
import net.sergeych.mp_logger.info
import net.sergeych.mp_logger.warning
import net.sergeych.mp_tools.encodeToBase64Compact
import net.sergeych.unikrypto.EncryptedBinaryStorage.Companion.checkPresence
import net.sergeych.unikrypto.EncryptedBinaryStorage.DecryptionFailed
import kotlin.random.Random

@Serializable
internal data class EncryptedStorageParams(
    val keyPrefix: String = "${randomId(5)}_",
    val nameSeed: ByteArray = Random.Default.nextBytes(32)
)

/**
 * The binary storage that encrypts stored data and hashes its keys. Keys are not encrypted as 1:1 encryption
 * may seriously weaken the key (as we can't use randomizing IV in this case or we wont't be able to access data by key
 * without scanning and decrypting all of them). Therefore, is is slightly different from usual storages:
 *
 * - it uses special key to encrypt vital data to access keys and a prefix to distinguish encrypted keys
 * - [keys] returns list of hashed keys, original names as for now can't be retrieved
 * - it is possible to retrieve data by both hashed or original key value.
 *
 * We may change keys politics and store also encrypted keys. Though it will seriously affect performance, so the
 * decision is not yet made. See also [checkPresence].
 *
 * Encrypted storage checks that provided key fits the storage, if it contains data but decrypting fails, it either
 * initialize storage clearing all existing data or throw an exception, depending on constructor arguments:
 *
 * @param source binary storage where encrytped data will be stored
 * @param encryptingKey key to encrypt data
 * @param clearOnError if true, when opeining storage with existing data but wrong key (decryption failure), all
 *          existing data will be wiped. Otherwise, the [DecryptionFailed] exception will be thrown.
 * @throws DecryptionFailed if provided key can't decrypt existing data (and there are data) and [clearOnError] is
 *          set to false.
 */
class EncryptedBinaryStorage(
    private val source: KVBinaryStorage,
    private val encryptingKey: SymmetricKey,
    clearOnError: Boolean = true
) : LogTag("EBKVS"), KVBinaryStorage {

    /**
     * The exception is thrown on construction if the procided key can't decrypt existing data and `clearOnError`
     * is set to false
     */
    class DecryptionFailed : Exception("failed to decypt ecnrypted storage")

    private val keyPrefix: String
    private val nameSeed: ByteArray

    private val hash = HashAlgorithm.SHA3_256

    init {
        debug { "initializing encrypted binary storage" }
        val params: EncryptedStorageParams = try {
            source[paramsKey]?.let {
                encryptingKey.etaDecrypt(it).decodeBoss<EncryptedStorageParams>().also {
                    info { "exising storage opened successfully" }
                }
            }
        } catch (t: Throwable) { // on JS platform crypto library exception is Throwable not Exception!
            if( clearOnError ) {
                warning { "fail to open existing storage, wiping it and creating new one" }
                null
            }
            else
                throw DecryptionFailed()
        }
            ?: EncryptedStorageParams().also {
                source.clear()
                source[paramsKey] = encryptingKey.etaEncrypt(BossEncoder.encode(it))
                info { "created new storage" }
            }
        keyPrefix = params.keyPrefix
        nameSeed = params.nameSeed
        debug { "storage ready" }
    }


    private fun prepareKey(key: String): String =
        if (key.startsWith(keyPrefix))
            key
        else
            "${keyPrefix}${hash.digest(nameSeed, key.encodeToByteArray()).encodeToBase64Compact()}"

    override val keys: Set<String>
        get() = source.keys.filter { it != paramsKey }.toSet()

    override fun get(key: String): ByteArray? =
        source[prepareKey(key)]?.let { encryptingKey.etaDecrypt(it) }

    override fun remove(key: String): ByteArray? = source.remove(prepareKey(key))?.let {
        // on remove we ignore decryption problems!
        kotlin.runCatching { encryptingKey.etaDecrypt(it) }.getOrNull()
    }

    override fun set(key: String, value: ByteArray) {
        source[prepareKey(key)] = encryptingKey.etaEncrypt(value)
    }

    companion object {
        /**
         * Check that the storage likely contain some encrypted binary storage.
         */
        fun checkPresence(storage: KVBinaryStorage): Boolean =
            storage[paramsKey]?.let { it.size > 16 } ?: false

        /**
         * Key to the encrypted initialization information. If this key presents, the storage could contain ecnrypoted
         * data. If value for this key is missing or currupted, encrypted storage can't be used and should be cleared.
         */
        val paramsKey = "f%j$$**yu3kjbhed_132"
    }
}