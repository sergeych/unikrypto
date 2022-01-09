package net.sergeych.unikrypto

actual fun ByteArray.toBase64(): String = Unicrypto.encode64(this)
actual fun String.decodeBase64(): ByteArray = Unicrypto.decode64(this).map { it.toByte() }.toByteArray()