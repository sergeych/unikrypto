import net.sergeych.unikrypto.HashAlgorithm
import net.sergeych.unikrypto.digest
import net.sergeych.unikrypto.encodeToHex
import kotlin.test.Test
import kotlin.test.assertEquals

class HashTestvector(val algorithm: HashAlgorithm, val source: String, resultHex: String) {
    val hex = resultHex.replace(" ", "")
}

val vectors = listOf(
    HashTestvector(
        HashAlgorithm.SHA256,
        "abc",
        "ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad"
    ),
    HashTestvector(
        HashAlgorithm.SHA512,
        "abc",
        "ddaf35a193617aba cc417349ae204131 12e6fa4e89a97ea2 0a9eeee64b55d39a 2192992a274fc1a8 36ba3c23a3feebbd 454d4423643ce80e 2a9ac94fa54ca49f"
    ),
    HashTestvector(
        HashAlgorithm.SHA3_256,
        "abc",
        "3a985da74fe225b2 045c172d6bd390bd 855f086e3e9d525b 46bfe24511431532"
    ),
    HashTestvector(
        HashAlgorithm.SHA3_384,
        "abc",
        "ec01498288516fc9 26459f58e2c6ad8d f9b473cb0fc08c25 96da7cf0e49be4b2 98d88cea927ac7f5 39f1edf228376d25"
    ),
    HashTestvector(
        HashAlgorithm.SHA3_512,
        "abc",
        "b751850b1a57168a 5693cd924b6b096e 08f621827444f70d 884f5d0240d2712e 10e116e9192af3c9 1a7ec57647e39340 57340b4cf408d5a5 6592f8274eec53f0"
    ),
)


class HashesTest {

    @Test
    fun testHashes() {
        return runTest {
            for (v in vectors) {
                assertEquals(v.hex, v.algorithm.digest(v.source).encodeToHex())
            }
        }
    }
}