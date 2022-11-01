import net.sergeych.mp_tools.encodeToBase64Compact
import net.sergeych.unikrypto.Safe58
import net.sergeych.unikrypto.encodeToHex
import kotlin.test.*

import kotlin.random.Random

internal class Safe58Test {

    @Test
    fun encode() {
        val source = Random.Default.nextBytes(16)

        assertContentEquals(source, Safe58.decode(Safe58.encode(source)))

        val encoded = Safe58.encodeWithCrc(source)
        println("-------------------------")
        println(encoded)
        println(encoded.chunkedSequence(5).joinToString("-") { it.toString() })
        assertContentEquals(source, Safe58.decodeWithCrc(encoded))
    }
}