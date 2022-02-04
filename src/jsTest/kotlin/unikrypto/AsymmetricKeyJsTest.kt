package net.sergeych.unikrypto

import net.sergeych.mp_tools.decodeBase64
import runTest
import kotlin.experimental.xor
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AsymmetricKeyJsTest {
    @Test
    fun testAssymmetricKey() {
        return runTest {
            val src = "Helluva".encodeToByteArray()
//            val k = Unicrypto.PrivateKey.generate(PrivateKeyParams(2048)).await()
            val x =
                "JgAcAQABvIDL1TsAhGRNgTvw5NW0CUBbfuvfs1AbxQ4lqdfYDIWuqu4yUINpVPFuW2J1IYYEUp536maBjM6753gWoysuVKhqLPwyZK0CTD7QK44dL0HTtTVuhri465PlUtdCg1RFoAMsUovumrAvahMutKra31aFt3eMj3D7K51pId6MyA8Ei7yAu3HtALLUDCQGX3AY7/z74dPNSgATyVgYiq0IJfmb0uspPmHtx1GA8S67xvH6L7wp79Prd1DJ2E8ZLKgNpFj/WlSN+dNGWEN0GVN7oxNnEtjxTHUJY0WRzvw7wJuEDfjQYBn+qcWBboRytJ6xkGNlp992FwQJuMOTOSi0rIRmTmE="
                    .decodeBase64()
            val k = Unicrypto.PrivateKey.unpackSync(x)

            println("\n>> $k")
            val s = k.signSync(src.toUint8Array(), SigningOptions()).toByteArray()
            println("\nnsig: $s")
            val pubk = k.publicKey
            println("\npub: ${pubk}")
            assertTrue { pubk.verifySync(src.toUint8Array(), s.toUint8Array(), SigningOptions()) }
            val updated = src.toTypedArray().toByteArray()
            updated[2] = updated[2] xor 0x17
            assertFalse { src contentEquals updated }
            assertFalse { pubk.verifySync(updated.toUint8Array(), s.toUint8Array(), SigningOptions()) }

            val i1 = k.publicKey.longAddress
            val i2 = k.publicKey.shortAddress
            println("\n\n> $i1")
//            val i2 = k.shortAddress
//
            assertTrue { i1.isMatchingKey(k) }
            assertTrue { i2.isMatchingKey(k) }
        }
    }

//    @Test
//    fun signatureIsCompatible1() {
//        val key = "HggcAQABxAABmm4/k4H32o+5lRxJkP5/Bthu1Cts7KEb1FJbpdbJJtlQx8gj6kF1l6lRTrbeIZV8Xc2lnsRBDQbh0x8yYFJ5Dgn4C8Htow0Sul947232IZPx07/ABs8JAmgeg6GBxtGswlAte2zENYr2ztK2f/AvkAIklov28N5DR3uXvk4Kp5A2q4dTBp3hy3wybs/ViSKEYM7Qv/lX/kfSsBV+fncd/v3EaPgVc365GdHW6sy4ekyfvnRTD0+eUEF9RA4B52xnx/3y4elXl3vTf0w83zb8eL/EyPiZVEtIxs1PP/A8f0EzTROd3kDeoTDs10dcT+OJyiaDpwPZpzzCRTr3LYvK2Q=="
//            .decodeBase64().let { AsymmetricKeys.unpackPublic(it)}
//        assertEquals("EFapEgInjWIY7E21rI0zrwcgNEg9Q1M7jrhOiWxbQfBtexgJQUAA42MfPLefbDZYNLlfUl0", key.id.asString)
//        val signature = "35498b9172649f78ba7d51a18afc42390739cde73d92248470c2cc293e6e77745bd1dee0fc691c72fdd3e8149c267bfbd50e612a9d96a1e855f1f57805e7b785003f3dc3bcbc1e96bf102176369b86e00f7ca3fca7d3f4404b051d055313f6d1dec3a767fd3ed38cd3e70decab2ba27f8b5d2e0f8e67909c9cb5229d4403bf240fb3b0f07772f8aadbb3734abdfad3bb89e71d9d3ab0634a8cdd5f0c7b82364c55b7c46fbe6e9ee682cdca614da317f5181010869ec576272633ba49030c9a6812a1b62ea24cda0afa93eb63a29cb5f47ed8dfa39bbdd04c0542bf8034a2c9d2aa0381ce5f1c105db524cc02bb419776df5f39f76f8734e3570f12d9f2b98961"
//            .decodeHex()
//        val message = "16050f4b504f57526573756c74442c07000000000000".decodeHex()
//        assertEquals("EFapEgInjWIY7E21rI0zrwcgNEg9Q1M7jrhOiWxbQfBtexgJQUAA42MfPLefbDZYNLlfUl0", key.universaKey.longAddress.asBinary.toByteArray().encodeToBase64Compact())
////        assertTrue { key.checkSignature(message, signature)}
//    }


//    @Test
//    fun signatureIsCompatible2() = runTest {
//        val packed = "HggcAQABxAABmm4/k4H32o+5lRxJkP5/Bthu1Cts7KEb1FJbpdbJJtlQx8gj6kF1l6lRTrbeIZV8Xc2lnsRBDQbh0x8yYFJ5Dgn4C8Htow0Sul947232IZPx07/ABs8JAmgeg6GBxtGswlAte2zENYr2ztK2f/AvkAIklov28N5DR3uXvk4Kp5A2q4dTBp3hy3wybs/ViSKEYM7Qv/lX/kfSsBV+fncd/v3EaPgVc365GdHW6sy4ekyfvnRTD0+eUEF9RA4B52xnx/3y4elXl3vTf0w83zb8eL/EyPiZVEtIxs1PP/A8f0EzTROd3kDeoTDs10dcT+OJyiaDpwPZpzzCRTr3LYvK2Q=="
//            .decodeBase64()
//
//        Unicrypto.unicryptoReady.await()
//
//        val key = Unicrypto.PublicKey.unpack(packed.toUint8Array()).await()
////            .let { AsymmetricKeys.unpackPublic(it)}
////        assertEquals("EFapEgInjWIY7E21rI0zrwcgNEg9Q1M7jrhOiWxbQfBtexgJQUAA42MfPLefbDZYNLlfUl0", key.longAddress.asString)
//        assertEquals("EFapEgInjWIY7E21rI0zrwcgNEg9Q1M7jrhOiWxbQfBtexgJQUAA42MfPLefbDZYNLlfUl0", key.longAddress.asBinary.toByteArray().encodeToBase64Compact())
//        val signature = "35498b9172649f78ba7d51a18afc42390739cde73d92248470c2cc293e6e77745bd1dee0fc691c72fdd3e8149c267bfbd50e612a9d96a1e855f1f57805e7b785003f3dc3bcbc1e96bf102176369b86e00f7ca3fca7d3f4404b051d055313f6d1dec3a767fd3ed38cd3e70decab2ba27f8b5d2e0f8e67909c9cb5229d4403bf240fb3b0f07772f8aadbb3734abdfad3bb89e71d9d3ab0634a8cdd5f0c7b82364c55b7c46fbe6e9ee682cdca614da317f5181010869ec576272633ba49030c9a6812a1b62ea24cda0afa93eb63a29cb5f47ed8dfa39bbdd04c0542bf8034a2c9d2aa0381ce5f1c105db524cc02bb419776df5f39f76f8734e3570f12d9f2b98961"
//            .decodeHex()
//        val message = "16050f4b504f57526573756c74442c07000000000000".decodeHex()
//
//        assertTrue { key.verify(message.toUint8Array(),signature.toUint8Array(),SigningOptions()).await()}
//    }



}