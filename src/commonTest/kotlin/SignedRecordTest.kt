import kotlinx.serialization.Serializable
import net.sergeych.mp_tools.decodeBase64
import net.sergeych.mp_tools.encodeToBase64
import net.sergeych.mp_tools.encodeToBase64Compact
import net.sergeych.mptools.toDump
import net.sergeych.unikrypto.AsymmetricKeys
import net.sergeych.unikrypto.SignedRecord
import net.sergeych.unikrypto.signRecord
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

@Serializable
data class T1(val foo: String)

@Serializable
data class PR(val POWResult: ByteArray)

class SignedRecordTest {

    @Test
    fun signedRecordTest() {
        return runTest {
            val k = AsymmetricKeys.generate(2048)
            val payload1 = T1("fake vaccine that kills")
            val packed = k.signRecord(payload1)
            println(packed.toDump())
            val sr = SignedRecord.unpack(packed)
            println(sr.payload)
            assertEquals(payload1, sr.decode())
            assertEquals(k.id, sr.publicKey.id)
        }
    }

    @Test
    fun compatibilityTest() {

        val b64 = "JgDECQEeCBwBAAHEAAGabj+Tgffaj7mVHEmQ/n8G2G7UK2zsoRvUUlul1skm2VDHyCPqQXWXqVFOtt4hlXxdzaWexEENBuHTHzJgUnkOCfgLwe2jDRK6X3jvbfYhk/HTv8AGzwkCaB6DoYHG0azCUC17bMQ1ivbO0rZ/8C+QAiSWi/bw3kNHe5e+TgqnkDarh1MGneHLfDJuz9WJIoRgztC/+Vf+R9KwFX5+dx3+/cRo+BVzfrkZ0dbqzLh6TJ++dFMPT55QQX1EDgHnbGfH/fLh6VeXe9N/TDzfNvx4v8TI+JlUS0jGzU8/8Dx/QTNNE53eQN6hMOzXR1xP44nKJoOnA9mnPMJFOvcti8rZxAABNUmLkXJkn3i6fVGhivxCOQc5zec9kiSEcMLMKT5ud3Rb0d7g/Gkccv3T6BScJnv71Q5hKp2WoehV8fV4Bee3hQA/PcO8vB6WvxAhdjabhuAPfKP8p9P0QEsFHQVTE/bR3sOnZ/0+04zT5w3sqyuif4tdLg+OZ5CcnLUinUQDvyQPs7Dwd3L4qtuzc0q9+tO7iecdnTqwY0qM3V8Me4I2TFW3xG++bp7mgs3KYU2jF/UYEBCGnsV2JyYzukkDDJpoEqG2LqJM2gr6k+tjopy19H7Y36ObvdBMBUK/gDSiydKqA4HOXxwQXbUkzAK7QZd2318592+HNONXDxLZ8rmJYbQWBQ9LUE9XUmVzdWx0RCwHAAAAAAAA"
        val packed = b64
            .decodeBase64()
        val u = packed.encodeToBase64()
        assertEquals(b64, u)
        val sr = SignedRecord.unpack(packed)
//        println(sr.publicKey.packed.encodeToBase64())
//        println(sr.publicKey.id.asString)
//        println(sr.nonce)
//        println(sr.type)
//        println(sr.payload)
//        println("00> ${sr.decode<PR>()}")
        assertContentEquals(byteArrayOf(44, 7, 0, 0, 0, 0, 0, 0), sr.decode<PR>().POWResult)
        assertEquals(SignedRecord.Type.RECORD_3_384, sr.type)
        assertEquals("EFapEgInjWIY7E21rI0zrwcgNEg9Q1M7jrhOiWxbQfBtexgJQUAA42MfPLefbDZYNLlfUl0", sr.publicKey.id.id.encodeToBase64Compact())
    }

//    @Test
//    fun signatureIsCompatible() {
//        val key = "HggcAQABxAABmm4/k4H32o+5lRxJkP5/Bthu1Cts7KEb1FJbpdbJJtlQx8gj6kF1l6lRTrbeIZV8Xc2lnsRBDQbh0x8yYFJ5Dgn4C8Htow0Sul947232IZPx07/ABs8JAmgeg6GBxtGswlAte2zENYr2ztK2f/AvkAIklov28N5DR3uXvk4Kp5A2q4dTBp3hy3wybs/ViSKEYM7Qv/lX/kfSsBV+fncd/v3EaPgVc365GdHW6sy4ekyfvnRTD0+eUEF9RA4B52xnx/3y4elXl3vTf0w83zb8eL/EyPiZVEtIxs1PP/A8f0EzTROd3kDeoTDs10dcT+OJyiaDpwPZpzzCRTr3LYvK2Q=="
//            .decodeBase64().let { AsymmetricKeys.unpackPublic(it)}
//        assertEquals("EFapEgInjWIY7E21rI0zrwcgNEg9Q1M7jrhOiWxbQfBtexgJQUAA42MfPLefbDZYNLlfUl0", key.id.asString)
//        val signature = "35498b9172649f78ba7d51a18afc42390739cde73d92248470c2cc293e6e77745bd1dee0fc691c72fdd3e8149c267bfbd50e612a9d96a1e855f1f57805e7b785003f3dc3bcbc1e96bf102176369b86e00f7ca3fca7d3f4404b051d055313f6d1dec3a767fd3ed38cd3e70decab2ba27f8b5d2e0f8e67909c9cb5229d4403bf240fb3b0f07772f8aadbb3734abdfad3bb89e71d9d3ab0634a8cdd5f0c7b82364c55b7c46fbe6e9ee682cdca614da317f5181010869ec576272633ba49030c9a6812a1b62ea24cda0afa93eb63a29cb5f47ed8dfa39bbdd04c0542bf8034a2c9d2aa0381ce5f1c105db524cc02bb419776df5f39f76f8734e3570f12d9f2b98961"
//            .decodeHex()
//        val message = "16050f4b504f57526573756c74442c07000000000000".decodeHex()
//        assertTrue { key.checkSignature(message, signature)}
//    }
/*
KeyId: EFapEgInjWIY7E21rI0zrwcgNEg9Q1M7jrhOiWxbQfBtexgJQUAA42MfPLefbDZYNLlfUl0
Signature: 35498b9172649f78ba7d51a18afc42390739cde73d92248470c2cc293e6e77745bd1dee0fc691c72fdd3e8149c267bfbd50e612a9d96a1e855f1f57805e7b785003f3dc3bcbc1e96bf102176369b86e00f7ca3fca7d3f4404b051d055313f6d1dec3a767fd3ed38cd3e70decab2ba27f8b5d2e0f8e67909c9cb5229d4403bf240fb3b0f07772f8aadbb3734abdfad3bb89e71d9d3ab0634a8cdd5f0c7b82364c55b7c46fbe6e9ee682cdca614da317f5181010869ec576272633ba49030c9a6812a1b62ea24cda0afa93eb63a29cb5f47ed8dfa39bbdd04c0542bf8034a2c9d2aa0381ce5f1c105db524cc02bb419776df5f39f76f8734e3570f12d9f2b98961
innerpack: 16050f4b504f57526573756c74442c07000000000000

KeyId: EFapEgInjWIY7E21rI0zrwcgNEg9Q1M7jrhOiWxbQfBtexgJQUAA42MfPLefbDZYNLlfUl0
Signature: 35498b9172649f78ba7d51a18afc42390739cde73d92248470c2cc293e6e77745bd1dee0fc691c72fdd3e8149c267bfbd50e612a9d96a1e855f1f57805e7b785003f3dc3bcbc1e96bf102176369b86e00f7ca3fca7d3f4404b051d055313f6d1dec3a767fd3ed38cd3e70decab2ba27f8b5d2e0f8e67909c9cb5229d4403bf240fb3b0f07772f8aadbb3734abdfad3bb89e71d9d3ab0634a8cdd5f0c7b82364c55b7c46fbe6e9ee682cdca614da317f5181010869ec576272633ba49030c9a6812a1b62ea24cda0afa93eb63a29cb5f47ed8dfa39bbdd04c0542bf8034a2c9d2aa0381ce5f1c105db524cc02bb419776df5f39f76f8734e3570f12d9f2b98961
innerpack: 16050f4b504f57526573756c74442c07000000000000

 */
}