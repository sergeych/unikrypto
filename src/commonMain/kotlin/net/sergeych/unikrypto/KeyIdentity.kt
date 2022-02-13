package net.sergeych.unikrypto

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import net.sergeych.mp_tools.decodeBase64Compact
import net.sergeych.mp_tools.encodeToBase64Compact
import kotlin.random.Random

/**
 * The key identity allows to compare and look for any [IdentifiableKey] instances in cryptographically safe manner,
 * e.g. providing no data that could help to compromise (bruteforce, etc) the key itself. For example, for symmetric
 * keys it is some independently generated random sequences, for private keys - some hashes of corresponding public
 * keys, and for password-derived ones some independently derived bytes.
 *
 * The implrtant thing about the ids is that keys with matching ids could be used together:
 *
 * - matching symmetric keys can be used to encrypt and decrypt data
 * - matching public and private keys can be sued to encrypt/verify and decrupt/sign correspondingly.
 *
 * KeyIdentities allow selecting keys from sort of keyrings: if the ids are matching, thecorresponding key _might_
 * be capable to process data, though it is important to try all keys with matching ids as it these are not necessarily
 * unique (though the probability of a clash is really low).
 *
 * Also for public and private keys identity could be used instead of comparing public keys for equality. While it is
 * possible in theory to exist several public key with matching identity the probability is negligible.
 * If, still, a guarantee is needed, compare packed public keys for equality.
 */
@Serializable
sealed class KeyIdentity {

    /**
     * Base of any id: binary sequence. __it is crucial that it never changes__: even calculated, it should be
     * the same on every invocation.
     */
    abstract val id: ByteArray

    /**
     * JS platform in fact does not allow Map<ByteArray,...> so we provide StringId to keep MP compatibility. This
     * key should be at least as good as [id].
     */
    open val stringId: String by lazy { id.encodeToBase64Compact() }

    /**
     * String representation of the identity. Could also be used to compare identity for matching.
     */
    open val asString: String get() = id.encodeToBase64Compact()

    override fun equals(other: Any?): Boolean = other?.let {
        if (other is KeyIdentity) id contentEquals other.id
        else false
    } ?: false

    override fun hashCode(): Int {
        if( id.size == 0 ) return 0
        return id.contentHashCode()
    }

    override fun toString(): String = asString
}

/**
 * Byte-sequence identity. Should be used when the identity could not be safely derived from the key itself (e.g.
 * symmetric keys, passwords, etc).
 */
@Serializable
@SerialName("BytesId")
class BytesId(override val id: ByteArray) : KeyIdentity() {

    companion object {
        fun fromString(data: String) = BytesId(data.decodeBase64Compact())
        fun random() = BytesId(Random.nextBytes(32))
    }
}

/**
 * Key identity that holds data necessary to derive a key from password using PBKDF2 algotithm.
 * Since it is serializable, it is easy to store PasswordID instance together with encrypted data
 * to be able later to decrypt it using a used-supplied password.
 *
 * Note that unikrypto suggest one password to prduce many cryptographically independent keys,
 * so the information specifying key position in generated data is inclued.
 */
@Suppress("unused")
@Serializable
@SerialName("PasswordId")
class PasswordId(
    override val id: ByteArray,
    val hashAlgorithm: HashAlgorithm,
    val rounds: Int,
    val keyLength: Int,
    val keyOffset: Int,
    val generatedLength: Int,
    val seed: ByteArray,
    val keyIdAlgorithm: Passwords.KeyIdAlgorithm = Passwords.KeyIdAlgorithm.Independent
) : KeyIdentity() {
    /**
     * Derive aend check a key in an effective way (e.g. caching PBKDF2 outputs for corresponding keys). Derived
     * key is always checked against the derived ID, so of the password is wrong, [InvalidPasswordError] will be
     * thrown.
     */
    suspend fun deriveKey(password: String): SymmetricKey =
        Passwords.Generator.generateKey(password, this)

    /**
     * Older password keys, [[Passwords.KeyIdAlgorithm.MyoCloud]], purposedly uses dependent ids on password key bunches,
     * for that reason we provide custom equality and strongly recommend to use passwordId as left part of the identity
     * operator expression. Newer keys uses independent ids, which is slower, but in some minor cases provide more
     * problematic cryptanalysis on encrypted data usage. Still, both key algorithms are equally strong against
     * data disclosure.
     *
     * Note that by default new ID algorithm is used and default serialization format deneds from myocloud.1 API.
     */
    override fun equals(other: Any?): Boolean {
        if( other is PasswordId ) {
            if(keyIdAlgorithm != Passwords.KeyIdAlgorithm.Independent ||
                other.keyIdAlgorithm != Passwords.KeyIdAlgorithm.Independent) {
                return id contentEquals other.id && generatedLength == other.generatedLength &&
                        keyLength == other.keyLength && keyOffset == other.keyOffset &&
                        seed contentEquals other.seed
            }
        }
        return super.equals(other)
    }

    /**
     * complete data on identity. Actually it is possible to restore [PasswordId] and regenerate key from password
     * from parsing this string.
     */
    override val stringId: String by lazy {
        "${super.stringId}:${seed.encodeToBase64Compact()}:$keyOffset:$keyLength:$generatedLength:$rounds${hashAlgorithm.name}"
    }

    override fun hashCode(): Int {
        var result = super.hashCode()
        result = 31 * result + id.contentHashCode()
        result = 31 * result + hashAlgorithm.hashCode()
        result = 31 * result + rounds
        result = 31 * result + keyLength
        result = 31 * result + keyOffset
        result = 31 * result + generatedLength
        result = 31 * result + seed.contentHashCode()
        result = 31 * result + keyIdAlgorithm.hashCode()
        return result
    }
}

/**
 * This method is not intended to be called directly, isntad, use [Passwords.deriveKeys] amd
 * [PasswordId.deriveKey]
 */
expect suspend fun PerformPBKDF2(
    password: String,
    size: Int,
    hash: HashAlgorithm,
    rounds: Int,
    salt: ByteArray): ByteArray

/**
 * The [KeyAddress] based [KeyIdentity] implementation used with asymmetric keys. _Attention! Unlike other
 * identities, here [asString] is not a base64 version of [id], instead, it used [KeyAddress] secure encoding
 * `Safe58` that reduces possibility of errors when the address is typed in by hand, also, its id includes
 * check code (crc) inside, so wrong KeyAddress and identity will most likely be detected on construction.
 *
 * This identity is automatically used with asymmetric keys. Comparing by id works normally. Just do not compare
 * asString with manually calculated base64. If you need to compare with string, be sure that the string is
 * obtained from constructed [KeyAddress] or [AddressId.asString].
 */
@Serializable
@SerialName("AddressId")
class AddressId(val address: KeyAddress): KeyIdentity() {

    constructor(bytes: ByteArray) : this(KeyAddress.of(bytes))

    override val id: ByteArray = address.asBytes

    override val asString: String by lazy { address.asString }
}