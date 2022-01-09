package net.sergeych.unikrypto

import java.util.*

actual fun ByteArray.toBase64(): String = Base64.getEncoder().encodeToString(this)
actual fun String.decodeBase64(): ByteArray = Base64.getDecoder().decode(this)