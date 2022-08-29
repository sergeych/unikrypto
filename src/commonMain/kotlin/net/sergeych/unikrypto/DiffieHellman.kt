package net.sergeych.unikrypto

import kotlinx.serialization.Serializable

val DH_CERTAINTY = 30
val DH_PRIME_SIZE = 512

@Serializable
data class DHExchange(
    val pub: ByteArray,
    val p: ByteArray,
    val g: ByteArray
)

expect class DiffieHellman {
    fun getExchange(): DHExchange
    fun init()
    fun proceed(exchange: DHExchange): ByteArray
    fun finalize(exchange: DHExchange): ByteArray
}