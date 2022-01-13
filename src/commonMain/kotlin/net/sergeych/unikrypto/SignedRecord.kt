package net.sergeych.unikrypto

import net.sergeych.boss_serialization.BossDecoder
import net.sergeych.boss_serialization_mp.BossEncoder
import net.sergeych.boss_serialization_mp.BossStruct
import net.sergeych.bossk.Bossk

/**
 * Simplified signed record used in many parsec cases. Allows signing by only one
 * key. It is not constructed but unpacked or packed using [SignedRecord.pack] and
 * [SignedRecord.unpack].
 */
@Suppress("unused")
class SignedRecord private constructor(
    val type: Type,
    val payload: BossStruct,
    val nonce: ByteArray?,
    val publicKey: VerifyingKey
) {
    /**
     * Known types of signed records
     */
    enum class Type(val code: Int) {
        RECORD_3_384(0),
        RECORD_3_256(1),
        RECORD_3_512(2),
        RECORD_2_256(3),
        RECORD_2_512(4);

        val hashAlgorithm by lazy {
            when (this) {
                RECORD_3_384 -> HashAlgorithm.SHA3_384
                RECORD_2_256 -> HashAlgorithm.SHA256
                RECORD_2_512 -> HashAlgorithm.SHA512
                RECORD_3_256 -> HashAlgorithm.SHA3_256
                RECORD_3_512 -> HashAlgorithm.SHA3_512
            }
        }

        companion object {
            val default = RECORD_3_384

            fun deocde(code: Int): Type {
                for (x in values()) {
                    if (x.code == code) return x
                }
                throw IllegalArgumentException("unknown SignedRecord type: $code")
            }
        }
    }

    /**
     * Decode payload using `kotlinx.serialization`. Be careful: signed records do not support
     * null payloads (as for now) and convert it to an empty structure {}, so deserialization may
     * fail.
     */
    inline fun <reified T>decode() = BossDecoder.decodeFrom<T>(payload)

    companion object {

        /**
         * Pack and sign the SignedRecord
         *
         * @param key     key to sign record with
         * @param payload any data to protect with a signatire. Should be either [BossStruct] oar a
         *                `kotlinx.serialization` type. Null value insert [BossStruct.EMPTY] as the format requires.
         * @param recordType the type of recirds defines hashing methon and inner structure. We **strongly recommend
         *                not to use Type.RECORD_2_256 anymore and migrate out from it wherever possible**.
         * @param nonce   optional byte array often used in parsec negotiations
         */
        suspend inline fun <reified T : Any?> pack(
            key: SigningKey,
            payload: T,
            nonce: ByteArray? = null,
            recordType: Type = Type.default,
        ): ByteArray {

            val data = Bossk.pack(
                arrayOf(
                    nonce,
                    payload?.let { BossEncoder.encodeToStruct(payload) } ?: BossStruct.EMPTY
                )
            )

            return Bossk.pack(
                arrayOf(
                    recordType.code,
                    key.publicKey.pack(),
                    key.sign(data, recordType.hashAlgorithm),
                    data
                )
            )
        }

        /**
         * Unpack signed record optinoally calling preCheck before verifying signature. As the
         * signature verification is a time-consuming process it is often useful to check data for
         * sanity first.
         *
         * @throws IllegalArgumentException if signature check fails, or structure is not as
         *                                  expected - only _after_ calling preCheck if present
         *
         * @param packed binary packed signed record
         * @param preCheck if present, is called with unpacked but not verified signed record
         *                 instance, so preCheck can, for example, throw and exception if the data
         *                 are not expected.
         */
        suspend fun unpack(packed: ByteArray, preCheck: ((SignedRecord) -> Unit)? = null): SignedRecord {
            val outer = Bossk.unpack<List<Any?>>(packed)
            val recordType = Type.deocde(outer[0] as? Int ?: badFormat())
            val key = AsymmetricKeys.unpackPublic(outer.bytesAt(1) ?: badFormat())

            val signature = outer.bytesAt(2) ?: badFormat()
            val innerPacked = outer.bytesAt(3) ?: badFormat()

            val inner = Bossk.unpack<List<Any?>>(innerPacked)
            val nonce = inner.bytesAt(0)

            val payload = inner.structAt(1) ?: BossStruct.EMPTY
            val record = SignedRecord(recordType, payload, nonce, key)

            preCheck?.invoke(record)

            if (!key.checkSignature(innerPacked, signature, record.type.hashAlgorithm))
                badFormat("invalid signature")

            return record
        }

        private fun badFormat(text: String = "invalid structure"): Nothing {
            throw IllegalArgumentException("SignedRecord: $text")
        }
    }
}

/**
 * Shortcut for [SignedRecord.pack]: packs a signed record using this key.
 */
suspend inline fun <reified T>SigningKey.signRecord(
    payload: T,
    nonce: ByteArray?=null,
    type: SignedRecord.Type=SignedRecord.Type.default
): ByteArray = SignedRecord.pack(this,payload, nonce, type)