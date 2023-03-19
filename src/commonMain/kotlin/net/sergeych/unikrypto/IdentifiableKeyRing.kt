@file:Suppress("UNCHECKED_CAST")

package net.sergeych.unikrypto

import kotlinx.serialization.Serializable

/**
 * Interface to anything that may provide identifiable keys. This class is not serializable and does not
 * provide polymorphic serialization. Instead, its most useful and simple implementors [Keyring], is serializable,
 * we recommend to use it in almost all cases.
 */
abstract class IdentifiableKeyring {
    /**
     * Allow iterating over all keys held in the ring
     */
    abstract val keys: Sequence<IdentifiableKey>

    /**
     * Get all the keys that match the dientity. It almost always return array of size 1 or 0, but for
     * rare occasions of [KeyIdentity] clash you dhould try it all. Btw [Container] does it automatically.
     */
    abstract operator fun get(keyIdentity: KeyIdentity): List<IdentifiableKey>

    /**
     * Check that the ring contains the specified identity
     */
    open operator fun contains(keyIdentity: KeyIdentity) = get(keyIdentity).isNotEmpty()

    operator fun contains(key: IdentifiableKey) = contains(key.id)

    /**
     * Size of the ring.
     */
    abstract val size: Int

    /**
     * Check that this rings contains all keys from the other rungs.
     */
    operator fun contains(other: IdentifiableKeyring): Boolean {
        for( k in other.keys) if( !contains(k.id) ) return false
        return true
    }

    /**
     * Check equality (same keys)
     */
    override fun equals(other: Any?): Boolean {
        return other is IdentifiableKeyring && other.size == size && contains(other)
    }

    override fun hashCode(): Int {
        var result = keys.hashCode()
        result = 31 * result + size
        return result
    }

    @Suppress("unused")
    @Deprecated("use byId... family")
    inline fun <reified T: IdentifiableKey>getAllMatching(ids: Collection<KeyIdentity>): Sequence<T> {
        val idSet = if( ids is Set<KeyIdentity>) ids else ids.toSet()
        return keys.filter { it.id in idSet && it is T  } as Sequence<T>
    }

    @Suppress("unused")
    fun byId(vararg ids: KeyIdentity): Sequence<IdentifiableKey> = byId(ids.toSet())

    fun byId(ids: Set<KeyIdentity>): Sequence<IdentifiableKey> = sequence {
        for( k in keys ) {
            if( k.id in ids ) yield(k)
        }
    }

    /**
     * Generate a sequence of (1) matching keys (2) other _symmetric_ keys: some old
     * symmetric keys may have wrong ID after reconstruction from key bytes, in which case
     * it is recommended to use this sequence
     */
    @Suppress("unused")
    fun byIdAndSymmetrics(vararg ids: KeyIdentity) = byIdAndSymmetrics(ids.toSet())

    /**
     * Generate a sequence of (1) matching keys (2) other _symmetric_ keys: some old
     * symmetric keys may have wrong ID after reconstruction from key bytes, in which case
     * it is recommended to use this sequence
     */
    fun byIdAndSymmetrics(ids: Set<KeyIdentity>) = sequence {
        // forsi matching
        yieldAll(byId(ids))
        // then symmetrics
        for( k in keys ) {
            if( k is SymmetricKey && k.id !in ids) yield(k)
        }
    }

}

/**
 * Very specific case immutable singlekey ring. optimized implementation.
 */
@Suppress("unused")
@Serializable
class SingleKeyring(val key: IdentifiableKey): IdentifiableKeyring() {
    override val keys: Sequence<IdentifiableKey> by lazy { sequence { yield(key) } }

    override fun get(keyIdentity: KeyIdentity): List<IdentifiableKey> =
        if (keyIdentity == key.id) listOf(key) else listOf()

    override fun contains(keyIdentity: KeyIdentity): Boolean = keyIdentity == key.id

    override val size = 1
}

/**
 * Entry for the [Keyring] allow to tag and to annotate keys.
 */
@Serializable
data class KeyEntry(
    @Serializable(with = IdentifiableKeySerializer::class)
    val key: IdentifiableKey,
    val tags: MutableSet<String> = mutableSetOf(),
    var comment: String? = null
)

/**
 * Most common _mutable keyring_. Contains mutable entries that combine immutable key with mutable
 * list of tags and optional comment. See [KeyEntry]
 */
@Suppress("unused")
@Serializable
class Keyring(val entries: MutableList<KeyEntry> = mutableListOf()): IdentifiableKeyring() {

    constructor(vararg keys: IdentifiableKey) : this( keys.map { KeyEntry(it) }.toMutableList())

    constructor(vararg taggedKeys: Pair<String,IdentifiableKey>) : this() {
        for( (tag, key) in taggedKeys) entries.add(KeyEntry(key, mutableSetOf(tag)))
    }


    override val keys: Sequence<IdentifiableKey> get() = sequence { for( e in entries ) yield(e.key) }

    override fun get(keyIdentity: KeyIdentity): List<IdentifiableKey> =
        entries.mapNotNull { if( keyIdentity == it.key.id) it.key else null }

    override val size: Int
        get() = entries.size

    /**
     * __Experimental__ return entries for all keys that have matching tags.
     */
    fun findByTags(vararg tags: String) =
        entries.filter { e ->
            tags.any { it in e.tags }
        }

    @Suppress("UNCHECKED_CAST")
    fun <T: IdentifiableKey>findById(id: KeyIdentity): T? =
        entries.firstOrNull {  it.key.id == id }?.key as T?
}