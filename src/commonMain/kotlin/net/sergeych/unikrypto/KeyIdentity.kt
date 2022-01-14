package net.sergeych.unikrypto

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
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

    abstract val id: ByteArray

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

@Suppress("unused")
@Serializable
@SerialName("PasswordId")
class PasswordId(
    override val id: ByteArray,
    val hashAlgorithm: HashAlgorithm,
    val rounds: Int,
    val keyLength: Int,
    val keyOffseet: Int,
    val generatedLength: Int,
    val seed: ByteArray
) : KeyIdentity() {

}

expect suspend fun PerformPBKDF2(
    password: String,
    size: Int,
    hash: HashAlgorithm,
    rounds: Int,
    salt: ByteArray): ByteArray

