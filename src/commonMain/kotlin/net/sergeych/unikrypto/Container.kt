package net.sergeych.unikrypto

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import net.sergeych.boss_serialization_mp.BossEncoder
import net.sergeych.boss_serialization_mp.decodeBoss
import net.sergeych.mp_logger.LogTag
import net.sergeych.mp_logger.Loggable
import net.sergeych.mp_logger.debug

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
 * To create container, use
 */
@Serializable
sealed class Container {
    abstract val keyIds: Set<KeyIdentity>
    abstract fun decrypt(key: DecryptingKey): ByteArray

    @Serializable
    @SerialName("single")
    data class Single(val keyId: KeyIdentity, val ciphertext: ByteArray): Container() {
        override val keyIds by lazy { setOf(keyId) }
        override fun decrypt(key: DecryptingKey): ByteArray = key.etaDecrypt(ciphertext)
    }

    @Serializable
    data class EncryptedKey(val id: KeyIdentity,val encryptedKey: ByteArray)

    @Serializable
    @SerialName("multi")
    data class Multiple(val keys: List<EncryptedKey>,val ciphertext: ByteArray): Container() {
        override val keyIds: Set<KeyIdentity> by lazy { keys.map { it.id }.toSet() }

        override fun decrypt(key: DecryptingKey): ByteArray {
            for( k in keys) {
                if( k.id == key.id ) {
                    val dataKey = SymmetricKeys.create( key.etaDecrypt(k.encryptedKey), k.id)
                    return dataKey.etaDecrypt(ciphertext)
                }
            }
            throw IllegalArgumentException("the key does not open this container")
        }

    }

    companion object : Loggable by LogTag("CRCON") {
        /**
         * Please use [encrypt] instead!
         */
        inline fun <reified T>single(payload: T,key: EncryptingKey): ByteArray {
            return BossEncoder.encode(Single(key.id, key.etaEncrypt(BossEncoder.encode(payload))) as Container)
        }

        /**
         * Please use [encrypt] instead!
         */
        inline fun <reified T>multi(payload: T,keys: List<EncryptingKey>): ByteArray {
            val dataKey = SymmetricKeys.random()
            return BossEncoder.encode(Multiple(
                keys.map { EncryptedKey(it.id, it.etaEncrypt(dataKey.packed)) },
                dataKey.etaEncrypt(BossEncoder.encode(payload))
            ) as Container)
        }

        /**
         * Preferred method to create encrypted container. Selects the type automatically. Decrypt it with
         * any of the provided key (their [DecryptingKey] counterparts) with [decrypt]
         *
         * @param payload data to encrypt. Could be `String`, `ByteArray` or any serializable type. Can't be null.
         * @param keys one or more keys to encrypt with.
         * @return encryped and packed container
         */
        inline fun <reified T>encrypt(payload: T,vararg keys: EncryptingKey) =
            when(keys.size) {
                0 -> throw IllegalArgumentException("provide at least one key")
                1 -> single(payload, keys[0])
                else -> multi(payload, keys.toList())
            }

        /**
         * Try to decrypt a container using some keys.
         *
         * @param keys to try to open the container.
         * @return the decrypted paylaod on success or null if no keys could open it.
         */
        inline fun <reified T>decrypt(packed: ByteArray,vararg keys: DecryptingKey): T? =
            decrypt<T>(packed, Keyring(*keys))

        /**
         * decrypt the container using leys in a keyring.
         * @return recrypted payload or null if no key from a keyring can open it.
         */
        inline fun <reified T>decrypt(packed: ByteArray,ring: IdentifiableKeyring): T? {
            val container = packed.decodeBoss<Container>()
            println("\n--\n")
            for( id in container.keyIds ) {
                if (id in ring)
                    for (key in ring[id]) {
                        if( key is DecryptingKey ) {
                            try {
                                return container.decrypt(key).decodeBoss()
                            }
                            catch(x: Exception) {
                                debug { "unexpected error while decrypting with matching key: $x" }
                            }
                        }
                    }
            }
            return null
        }
    }
}
