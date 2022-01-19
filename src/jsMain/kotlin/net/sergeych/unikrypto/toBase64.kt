package net.sergeych.unikrypto

actual fun ByteArray.toBase64(): String = Unicrypto.encode64(this)

// there is a problem: unicrypto unpacks to Uint8Array which is poorly supported by kotlin
// and in this case it will be different unless converted manually
actual fun String.decodeBase64(): ByteArray = Unicrypto.decode64(this).toByteArray()