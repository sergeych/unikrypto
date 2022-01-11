package net.sergeych.unikrypto

interface KeyIdentity {
    fun matches(obj: Any): Boolean
    val asByteArray: ByteArray
    val asString: String
}

abstract class GenericKeyIdentity: KeyIdentity {
    override fun equals(other: Any?): Boolean = other?.let { matches(it) } ?: false

    override fun toString(): String {
        return "KI:$asString"
    }
}


class BytesId(val id: ByteArray): GenericKeyIdentity() {
    override fun matches(obj: Any): Boolean {
        return (obj is BytesId) && obj.id contentEquals id
    }
    override val asByteArray: ByteArray
        get() = id
    override val asString: String
        get() = id.toBase64Compact()

    companion object {
        fun fromString(data: String) = BytesId(data.decodeBase64Compact())
    }
}

