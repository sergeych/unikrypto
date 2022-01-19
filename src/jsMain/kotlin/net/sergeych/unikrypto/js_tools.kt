@file:Suppress("unused")

package net.sergeych.unikrypto

import org.khronos.webgl.ArrayBuffer
import org.khronos.webgl.Uint8Array
import org.khronos.webgl.get

fun ArrayBuffer.toByteArray(): ByteArray = Uint8Array(this).toByteArray()

fun Uint8Array.toByteArray(): ByteArray {
    val result = ByteArray(length)
    for( i in 0 until length)
        result[i] = this.get(i)
    return result
}

fun ArrayBuffer?.toByteArray(): ByteArray? = this?.run { Uint8Array(this).toByteArray() }
fun Uint8Array?.toByteArray(): ByteArray? = this?.run { Uint8Array(this).toByteArray() }
