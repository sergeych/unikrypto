package net.sergeych.unikrypto

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
interface KeyIdentity {
    /**
     * Check that some identity matches this one. This fun _must be used in equality operator_ in any
     * in implementation.
     */
    fun matches(obj: Any): Boolean

    /**
     * Represent identity as binary data. The identities with equal binary are matching.
     */
    val asByteArray: ByteArray

    /**
     * String representation of the identity. Could also be used to compare identity for matching.
     */
    val asString: String
}

/**
 * Helper class that implements equality operator using [matches] and provides [hashCode] based on [asString]
 * representation.
 */
abstract class GenericKeyIdentity: KeyIdentity {
    override fun equals(other: Any?): Boolean = other?.let { matches(it) } ?: false

    override fun hashCode(): Int = asString.hashCode()

    override fun toString(): String {
        return "KI:$asString"
    }
}

/**
 * Byte-sequence identity. Should be used when the identity could not be safely derived from the key itself (e.g.
 * symmetric keys, passwords, etc).
 */
class BytesId(val id: ByteArray): GenericKeyIdentity() {
    override fun matches(obj: Any): Boolean {
        return (obj is BytesId) && obj.id contentEquals id
    }
    override val asByteArray: ByteArray
        get() = id
    override val asString: String
        get() = id.encodeToBase64Compact()

    companion object {
        fun fromString(data: String) = BytesId(data.decodeBase64Compact())
    }
}

