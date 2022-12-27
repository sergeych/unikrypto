package net.sergeych.unikrypto

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import net.sergeych.boss_serialization_mp.BossEncoder
import net.sergeych.boss_serialization_mp.decodeBoss
import net.sergeych.mp_logger.LogTag
import net.sergeych.mp_logger.Loggable

/**
 * the serializable space effective crypto-container allowing to encrypt content for one or more keys of any
 * type that implements [EncryptingKey], user on creation, and [DecryptingKey], used when unpacking it.
 *
 * To reduce container size, it is polymorphic with two types: single and multi. Single container is simple,
 * it contains encrypting key and encrypted payload. Multi-key container instead uses random key to encrypt
 * the payload, and the key itself is encrypted with any recipient keys provided on creation. When using private keys
 * of great strength, its minimum size could be lrge enough to hold the pyload, so use separate type for
 * sinlge-key container pays itself. Also. BOSS codec caches strings in data so most text fields after the
 * first appearance will be coded with as little as 1 byte at first, or 2 and maybe even 3 if there are too many
 * strings ;)
 *
 * Important feature of the container is ability to re-encrypt it using any one known key, keeping it available
 * to all other keys unknown at the update time.
 *
 * Usually all you need is to call companion object methods.
 *
 * Please note that methods throws following excetpions on typical failures:
 *
 * - [Container.Error] if it fails to decode and decrypt the container, more precisely
 *   its chidlred [Container.DecryptionError] if decryption failed and [Container.StructureError]
 *   if it fails to decode the container inner structure.
 *
 * - `IllegalArgumentException` if there is no suitable key in the provided keyring.
 */
@Suppress("OPT_IN_USAGE")
@Serializable
sealed class Container {


    /**
     * Gegenral error while unpacking and decrypting the container
     */
    open class Error(reason: String = "failed to process the container") : IllegalArgumentException(reason)

    /**
     * Decryption failed
     */
    class DecryptionError : Error("failed to decrypt the continer")

    /**
     * Packed container seems to be corrupted
     */
    class StructureError : Error("inllegal container structure")

    /**
     * Key Ids for the key that can dectypt the container
     */
    abstract val keyIds: Set<KeyIdentity>
    abstract fun decrypt(key: DecryptingKey): ByteArray

    abstract fun update(keyRing: IdentifiableKeyring, newData: ByteArray): ByteArray?

    fun selectKeys(keyRing: IdentifiableKeyring) = keyRing.getAllMatching<DecryptingKey>(keyIds)

    fun decrypt(keyRing: IdentifiableKeyring): Pair<IdentifiableKey, ByteArray>? {
        for (k in selectKeys(keyRing)) {
            try {
                return k to decrypt(k)
            } catch (x: Throwable) {
                throw DecryptionError()
            }
        }
        return null
    }

    @Serializable
    @SerialName("single")
    data class Single(val keyId: KeyIdentity, val ciphertext: ByteArray) : Container() {
        override val keyIds by lazy { setOf(keyId) }
        override fun decrypt(key: DecryptingKey): ByteArray = try {
            key.etaDecrypt(ciphertext)
        }
        catch(x: Exception) {
            throw x
        }

        override fun update(keyRing: IdentifiableKeyring, newData: ByteArray): ByteArray? {
            return decrypt(keyRing)?.let { (k, _) ->
                if (k !is EncryptingKey) throw IllegalArgumentException("key is not suitable for re-encryption")
                encryptData(newData, k)
            }
        }
    }

    @Serializable
    data class EncryptedKey(val id: KeyIdentity, val encryptedKey: ByteArray)

    @Serializable
    @SerialName("multi")
    data class Multiple(val keys: List<EncryptedKey>, val ciphertext: ByteArray) : Container() {
        override val keyIds: Set<KeyIdentity> by lazy { keys.map { it.id }.toSet() }

        override fun decrypt(key: DecryptingKey): ByteArray {
            for (k in keys) {
                if (k.id == key.id) {
                    val dataKey = SymmetricKeys.create(key.etaDecrypt(k.encryptedKey), k.id)
                    try {
                        return dataKey.etaDecrypt(ciphertext)
                    }
                    catch(x: Exception) {
                        throw DecryptionError()
                    }
                }
            }
            throw IllegalArgumentException("the key does not open this container")
        }

        override fun update(keyRing: IdentifiableKeyring, newData: ByteArray): ByteArray? {
            for (k in keys) {
                for (key in keyRing[k.id]) {
                    if (key is DecryptingKey) {
                        val dataKey = SymmetricKeys.create(key.etaDecrypt(k.encryptedKey), k.id)
                        return BossEncoder.encode(Multiple(keys, dataKey.etaEncrypt(newData)) as Container)
                    }
                }
            }
            return null
        }
    }


//            return decrypt(keyRing)?.let { (key,_) ->
//                if(key !is EncryptingKey) throw IllegalArgumentException("key is not suitable for re-encryption")
//                if(key !is DecryptingKey) throw IllegalArgumentException("key is not suitable for re-encryption (not decrypting!)")
//                val dataKey = SymmetricKeys.create( key.etaDecrypt(k.encryptedKey), k.id)
//                encryptData(newData,k)
//            }
//        }
//    }

    companion object : Loggable by LogTag("CRCON") {
        /**
         * Create single-key container. Most often you should call [encrypt] instead.
         */
        fun single(payload: ByteArray, key: EncryptingKey): ByteArray {
            return BossEncoder.encode(Single(key.id, key.etaEncrypt(payload)) as Container)
        }

        /**
         * Create nultiple keys container event with one key. Most often you should not call it but
         * use [encrypt] instead.
         */
        fun multi(payload: ByteArray, keys: List<EncryptingKey>): ByteArray {
            val dataKey = SymmetricKeys.random()
            return BossEncoder.encode(
                Multiple(
                    keys.map { EncryptedKey(it.id, it.etaEncrypt(dataKey.packed)) },
                    dataKey.etaEncrypt(payload)
                ) as Container
            )
        }

        /**
         * Preferred method to create encrypted container. Selects the type automatically. Decrypt it with
         * any of the provided key (their [DecryptingKey] counterparts) with [decrypt]
         *
         * @param payload data to encrypt. Could be `String`, `ByteArray` or any serializable type. Can't be null.
         * @param keys one or more keys to encrypt with.
         * @return encryped and packed container
         */
        inline fun <reified T> encrypt(payload: T, vararg keys: EncryptingKey): ByteArray =
            encryptData(BossEncoder.encode(payload), *keys)

        /**
         * Encrypt payload  as is, without boss serialization. See [encrypt] for details.
         * @return encrypted packed container
         */
        fun encryptData(payload: ByteArray, vararg keys: EncryptingKey): ByteArray =
            when (keys.size) {
                0 -> throw IllegalArgumentException("provide at least one key")
                1 -> single(payload, keys[0])
                else -> multi(payload, keys.toList())
            }

        /**
         * Update packed container using proper key in the ring with a new payload. This function os useful
         * when the container could be multiple (but it works with any) and we know only one of its keys,
         * but want to change the data. It is possible as any of the keys could be used to re-encrypt data
         * that _will be available to all other keys_.
         * @param payload packed container
         * @param keyRing keyring which should contain at least one key that can decrypt the contatiner
         * @param packed new payload to encrypt
         * @return packed encrypted container with new payload or null if keyring can't decrypt it
         */
        inline fun <reified T> update(packed: ByteArray, keyRing: IdentifiableKeyring, payload: T): ByteArray? {
            return packed.decodeBoss<Container>().update(keyRing, BossEncoder.encode(payload))
        }

        /**
         * Try to decrypt a container using some keys.
         *
         * @param keys to try to open the container.
         * @return the decrypted paylaod on success or null if no keys could open it.
         */
        inline fun <reified T> decrypt(packed: ByteArray, vararg keys: DecryptingKey): T? =
            decrypt<T>(packed, Keyring(*keys))

        /**
         * decrypt the container using leys in a keyring.
         * @return recrypted payload or null if no key from a keyring can open it.
         */
        inline fun <reified T> decrypt(packed: ByteArray, ring: IdentifiableKeyring): T? {
            return decryptAsBytes(packed, ring)?.decodeBoss<T>()
        }

        fun decryptAsBytes(packed: ByteArray, ring: IdentifiableKeyring): ByteArray? =
            protect {
                packed.decodeBoss<Container>().decrypt(ring)?.second
            }

        fun decryptAsBytes(packed: ByteArray, vararg keys: DecryptingKey): ByteArray? =
            protect {
                packed.decodeBoss<Container>().decrypt(Keyring(*keys))?.second
            }

        private inline fun <reified T> protect(f: () -> T): T =
            try {
                f()
            }
            catch(x: DecryptionError) {
                throw x
            }
            catch (x: Exception) {
                throw StructureError()
            }
    }
}
