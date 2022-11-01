import net.sergeych.unikrypto.Safe58
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals

internal class Safe58Test {

    @Test
    fun encode() {
        val source = Random.Default.nextBytes(17)

        assertContentEquals(source, Safe58.decode(Safe58.encode(source)))

        val encoded = Safe58.encodeWithCrc(source)
        println("-------------------------")
        println(encoded)
        println(encoded.chunkedSequence(5).joinToString("-"))
        assertContentEquals(source, Safe58.decodeWithCrc(encoded))
    }
}