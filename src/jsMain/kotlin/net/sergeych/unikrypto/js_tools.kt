package net.sergeych.unikrypto

import org.khronos.webgl.ArrayBuffer
import org.khronos.webgl.Uint8Array

fun ArrayBuffer.toByteArray(): ByteArray = Uint8Array(this).unsafeCast<ByteArray>()

fun ArrayBuffer?.toByteArray(): ByteArray? = this?.run { Uint8Array(this).unsafeCast<ByteArray>() }
