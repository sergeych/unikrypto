@file:Suppress("SERIALIZER_TYPE_INCOMPATIBLE")

package net.sergeych.unikrypto

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import net.sergeych.bossk.FormatException
import net.sergeych.mp_tools.encodeToBase64Compact
import kotlin.random.Random

/**
 * Hash methods used in new uniKrypto library. older hashes are intentionally not listed (at least so far)
 */
enum class HashAlgorithm {
    SHA3_256, SHA3_384, SHA3_512,
    SHA256, SHA512;

    /**
     * Convert to a string representation used in Universa notation
     */
    fun toUniversa(): String = name.lowercase()
    // "sha256" | "sha384" | "sha512" | "sha512/256" | "sha3_256" | "sha3_384" | "sha3_512";
}

expect fun HashAlgorithm.digest(vararg source: ByteArray): ByteArray

fun HashAlgorithm.digest(text: String): ByteArray = digest(text.encodeToByteArray())

/**
 * Universa MP key. It _has an identity_ and could be packed to binary
 * representation. Any particular key though implements some of [EncryptingKey], [DecryptingKey],
 * [SigningKey] and [VerifyingKey] interfaces. Use the needed interface instead of archetypes
 * like [PublicKey] wherever possible.
 *
 * __Note on serialization__. Because of some complications of kollinx serialization and openedness of the
 * keys system, it is necessary to declare serializer to each IdentifiableKey (or descenfants) properties,
 * it must look like:
 * ```kotlin
 * @Serializable
 * data class KeyEntry(
 *
 *     @Serializable(with = IdentifiableKeySerializer::class)
 *     val key: IdentifiableKey,
 *
 *     val tags: MutableList<String> = mutableListOf(),
 *     var comment: String? = null
 * )
 * ```
 */
interface IdentifiableKey {
    /**
     * Identity lets smart compare keys without allowing making any assumptions or somehow else reduce the
     * strength of the key it identifies. Also, identities of the public and private keys are matching, so
     * it should be used to check where some part of asymmetric key matches another. See [KeyIdentity]
     */
    val id: KeyIdentity

    /**
     * Pack to binary form without applying passwords, etc.
     */
    val packed: ByteArray
}

/**
 * The ley capable of encrypting and authenticating (EtA) plain data
 */
interface EncryptingKey: IdentifiableKey {
    /**
     * Encrypt then authenticate binary data, what means any attempt to tamper encrypted data will be
     * detected and reported. The EtA algorithm does not reduce strength of the encryption not allowing
     * making any assumptions on the used key.
     */
    fun etaEncrypt(plaintext: ByteArray): ByteArray = throw OperationNotSupported()
    /**
     * Encrypt then authenticate string data using utf-8 format.
     */
    fun etaEncrypt(plaintext: String): ByteArray = etaEncrypt(plaintext.encodeToByteArray())
}

/**
 * Key capable to decrypt and check authentication of ciphered data. Note that corresponding key will have
 * matching [id]
 */
interface DecryptingKey: IdentifiableKey {
    /**
     * Decrypt the data using incorporated authenticity (EtA algorithm). It means, that id the key is wrong or the
     * encrypted data were tampered, decryption will fail with exception.
     */
    fun etaDecrypt(ciphertext: ByteArray): ByteArray = throw OperationNotSupported()

    /**
     * Decrypt the text data using utf-8 encoding and check the authenticity. If the key is wrong or encrypted data
     * was modified, throws an exception.
     */
    fun etaDecryptToString(ciphertext: ByteArray): String = etaDecrypt(ciphertext).decodeToString()
}

/**
 * Key capable of signing data.
 */
interface SigningKey: IdentifiableKey {
    /**
     * Sign arbitrary data with this key.
     */
    fun sign(data: ByteArray, hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA3_384): ByteArray =
        throw OperationNotSupported()

    /**
     * Sign text data with this key using utf-8 encoding
     */
    fun sign(text: String,hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA3_384): ByteArray
            = sign(text.encodeToByteArray(), hashAlgorithm)

    val publicKey: VerifyingKey
}

/**
 * Key capable fo verifying signature. Tha corresponding key will have matching [id]
 */
interface VerifyingKey: IdentifiableKey {
    /**
     * Check the signature of binary data. Note that hash algorithm should be the same as used when signing.
     */
    fun checkSignature(
        data: ByteArray,
        signature: ByteArray,
        hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA3_384
    ): Boolean = throw OperationNotSupported()

    /**
     * Check the signature of the text that was encoded with utf-8. Note that hash algorithm should be the same as
     * used when signing.
     */
    fun checkSignature(
        text: String,
        signature: ByteArray,
        hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA3_384
    ): Boolean = checkSignature(text.encodeToByteArray(), signature, hashAlgorithm)
}
/**
 * Symmetric key is one that can encrypt and decrypt data, but can not sign or verify signatures.
 * It uses simple equality-based independent IDs not derivable from the key (but possibly derivable from password
 * but in independent manner)
 */
@Serializable(with = IdentifiableKeySerializer::class)
abstract class SymmetricKey(override val id: KeyIdentity): EncryptingKey, DecryptingKey {
    abstract val keyBytes: ByteArray
    companion object {
        @Suppress("unused")
        fun SymmetricKey(keyBytes: ByteArray, id: KeyIdentity?=null): SymmetricKey =
            SymmetricKeys.create(keyBytes, id ?: BytesId.random())

        @Suppress("unused")
        fun SymmetricKey() = SymmetricKeys.random()
    }

    override fun toString(): String =
        "SymmetricKey(${keyBytes.encodeToBase64Compact()}"
}

/**
 * Platform-specific fabric for symmetric keys
 */
interface SymmetricKeyProvider {
    val keySizes: Array<Int>
    fun create(keyBytes: ByteArray,id: KeyIdentity = BytesId(Random.Default.nextBytes(32))): SymmetricKey
    fun random(): SymmetricKey
}

/**
 * Platform-dependent factory to create symmetric keys
 */
expect val SymmetricKeys: SymmetricKeyProvider

/**
 * Public key is a key capable of encrypting and verifying signatures. It has some specific fields that extend these
 * interfaces
 */
@Serializable(with = IdentifiableKeySerializer::class)
abstract class PublicKey: EncryptingKey, VerifyingKey  {

    /**
     * Bits strength. Usually it also means the block size (as (strength+7)/8 but most often strength os a power of 2
     * so block size is just strength/8)
     */
    abstract val bitStrength: Int

    /**
     * The maximum size of the message that fits the block of the algorithm. This implementation works for RSA OAEP
     * with 32-bytes (256 bits) hashes used for padding. Other implementation must override it to make
     * [etaEncrypt] work.
     */
    protected open val maxMessageSize by lazy {
        // for SHA256 or SHA3_256 overhead is:
        bitStrength/8 - 32 * 2 - 2
    }

    /**
     * The size of the encryption block, usually is bitStrength/8. No ciphertext could be less than this block.
     * It is used by [etaEncrypt] to properly handle long plaintexts. Implementation must override it if it
     * differs from this version, which is good for RSA with ket sizes of powers of 2.
     */
    open val minimumEncryptedSize by lazy {
        bitStrength/8
    }

    /**
     * Implement block encryption (slow). Result should be exactly [minimumEncryptedSize] in length.
     */
    protected abstract fun encryptBlock(plaintext: ByteArray): ByteArray

    /**
     * Encrypt data of any length uses compatible size extension algorithm. If the plaintext fits the single block,
     * it is simply encrypted in it. Otherwise, the random symmetric key is generated and encrypted message is
     * prepared as concatenation of a key itself and the plaintext encrypted with it. Then the initial part of the
     * encrypted message is encrypted with this public key (therefore, protecting the symmetric key) and the
     * rest part of the message simply follows the encrypted block. This method conserves space and preserves
     * compatibility with most old unicrypto-related formats.
     */
    override fun etaEncrypt(plaintext: ByteArray): ByteArray {
        if( plaintext.size <= maxMessageSize ) return encryptBlock(plaintext)
        val k = SymmetricKeys.random()
        val encodedMessage = k.packed + k.etaEncrypt(plaintext)

        val part1 = encodedMessage.sliceArray(0 until maxMessageSize )
        val part2 = encodedMessage.sliceArray( maxMessageSize until encodedMessage.size)

        return encryptBlock(part1) + part2
    }
}

/**
 * The private key is capable of decrypting and signing. It also has unique ability to provide corresponding
 * public key.
 */
@Serializable(with = IdentifiableKeySerializer::class)
abstract class PrivateKey: DecryptingKey, SigningKey  {

    abstract override val publicKey: PublicKey

    /**
     * Pack a key to universa format with a password amd PBKDF procedure. We recommend to use other
     * formats, like encrypting the keyring, as encrypting every key is too resource consuming. Mainly to
     * provide compatibility with older universa files
     */
    abstract suspend fun packWithPassword(password: String): ByteArray

    /**
     * Platform-specific method to decrypt a block. The block size should be `publicKey.minimumEncryptedSize` exactly.
     * [etaDecrypt] implementation uses it to decrypt long and short data simultaneously.
     */
    protected abstract fun decryptBlock(ciphertext: ByteArray): ByteArray

    /**
     * Decrypt data of any size. Short data are just encrypted in the only block of the asymmetric algorithms, long
     * data is decrypted from encrypted message, as described in [PublicKey.etaEncrypt], see details there.
     */
    override fun etaDecrypt(ciphertext: ByteArray): ByteArray {
        val puk = publicKey
        if( ciphertext.size < puk.minimumEncryptedSize )
            throw UnikryptoError("encrypted block is too small: ${ciphertext.size} should be >= ${puk.minimumEncryptedSize}")
        if( ciphertext.size == puk.minimumEncryptedSize )
            return decryptBlock(ciphertext)

        val part1 = decryptBlock(ciphertext.sliceArray(0 until puk.minimumEncryptedSize))
        val part2 = ciphertext.slice(puk.minimumEncryptedSize until ciphertext.size)
        val encodedMessage = part1 + part2

        val key = SymmetricKeys.create(encodedMessage.sliceArray(0 .. 31))
        return key.etaDecrypt(encodedMessage.sliceArray(32 until encodedMessage.size))
    }
}

/**
 * Platform-dependent provider for asymmetric keys
 */
interface AsymmetricKeysProvider {
    /**
     * Generate new private+public key pair of a given strength. 2048, 4096 and 8192 bits strength is
     * supported. Could be slow in browsers that do not support wasm. USes worker in browsers when supported.
     */
    suspend fun generate(bitStrength: Int): PrivateKey
    fun unpackPublic(data: ByteArray): PublicKey
    fun unpackPrivate(data: ByteArray): PrivateKey
    /**
     * Generate new private+public key pair of a given strength. 2048, 4096 and 8192 bits strength is
     * supported. Could be slow in browsers that do not support wasm. USes worker in browsers when supported.
     */
    suspend fun decryptPrivateKey(data: ByteArray, password: String): PrivateKey

    suspend fun unpackKeyId(packedKeyId: ByteArray): KeyIdentity
    suspend fun unpackKeyId(packedKeyIdString: String): KeyIdentity
}


@Serializable
internal data class IdentifiableKeySurrogate(
    val id: KeyIdentity? = null,
    val type: String,
    val packed: ByteArray
)

/**
 * Platform-dependent implementation of asymmetric keys
 */
expect val AsymmetricKeys: AsymmetricKeysProvider

object IdentifiableKeySerializer : KSerializer<IdentifiableKey> {
    override fun deserialize(decoder: Decoder): IdentifiableKey {
        val s = decoder.decodeSerializableValue(IdentifiableKeySurrogate.serializer())
        return when(s.type) {
            "public" -> AsymmetricKeys.unpackPublic(s.packed)
            "private" -> AsymmetricKeys.unpackPrivate(s.packed)
            "symmetric" -> SymmetricKeys.create(s.packed, s.id!!)
            else -> throw FormatException("unknown key type found")
        }
    }

    override val descriptor: SerialDescriptor = IdentifiableKeySurrogate.serializer().descriptor

    override fun serialize(encoder: Encoder, value: IdentifiableKey) {
        val s = when(value) {
            is PublicKey -> IdentifiableKeySurrogate(null, "public", value.packed)
            is PrivateKey -> IdentifiableKeySurrogate(null, "private", value.packed)
            is SymmetricKey -> IdentifiableKeySurrogate(value.id, "symmetric", value.packed)
            else -> throw SerializationException("don't knwo how to serialize key $value")
        }
        encoder.encodeSerializableValue(IdentifiableKeySurrogate.serializer(),s)
    }

}