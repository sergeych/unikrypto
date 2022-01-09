package net.sergeych.unikrypto

expect fun ByteArray.toBase64(): String
expect fun String.decodeBase64(): ByteArray

private val reSpaces = Regex("\\s+")

fun String.decodeBase64Compact(): ByteArray {
    var x = StringBuilder(reSpaces.replace(this, ""))
    while( x.length % 4 != 0 ) x.append('=')
    return x.toString().decodeBase64()
}

fun ByteArray.toBase64Compact(): String {
    val result = toBase64()
    var end = result.length-1
    while( end > 0 && result[end] == '=') end--
    return result.slice(0..end)
}
