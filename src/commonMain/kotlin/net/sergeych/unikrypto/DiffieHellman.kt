import kotlinx.serialization.Serializable

val DH_CERTAINTY = 30
val DH_PRIME_SIZE = 512

@Serializable
data class DHExchange(
    val pub: ByteArray,
    val p: ByteArray,
    val g: ByteArray
)

abstract class DiffieHellmanAbstract {
    abstract val key: ByteArray?

    abstract fun init(): Unit
    abstract fun proceed(exchange: DHExchange): Unit
    abstract fun finalize(exchange: DHExchange): Unit
    abstract fun getExchange(): DHExchange
}