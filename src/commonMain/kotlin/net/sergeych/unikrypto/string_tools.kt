package net.sergeych.unikrypto

expect fun ByteArray.toBase64(): String
expect fun String.decodeBase64(): ByteArray

private val reSpaces = Regex("\\s+")

/**
 * Decode compact representation of base64. e.g. with oissibly no trailing '=' fill characters, for example,
 * encoded with [ByteArray.encodeToBase64Compact] fun.
 */
fun String.decodeBase64Compact(): ByteArray {
    val x = StringBuilder(reSpaces.replace(this, ""))
    while( x.length % 4 != 0 ) x.append('=')
    return x.toString().decodeBase64()
}

/**
 * Encode to base64 with no spaces and no trailing '=' fill characters, to be decoded with [String.decodeBase64Compact].
 */
fun ByteArray.encodeToBase64Compact(): String {
    val result = toBase64()
    var end = result.length-1
    while( end > 0 && result[end] == '=') end--
    return result.slice(0..end)
}

private val hexDigits = "0123456789abcdef"

fun ByteArray.encodeToHex(): String {
    val result = StringBuilder()
    for( b in this) {
        val u = b.toInt()
        result.append(hexDigits[(u shr 4) and 0x0f])
        result.append(hexDigits[u and 0x0f])
    }
    return result.toString()
}