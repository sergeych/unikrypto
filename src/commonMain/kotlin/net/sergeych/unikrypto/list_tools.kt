package net.sergeych.unikrypto

import net.sergeych.boss_serialization_mp.BossStruct
import net.sergeych.bossk.FormatException

fun <T>List<T>.bytesAt(index: Int): ByteArray? = this[index] as? ByteArray

fun <T>List<T>.structAt(index: Int): BossStruct? {
    val item = this[index]
    return when(item) {
        null -> null
        is BossStruct -> item
        is Map<*,*> -> BossStruct.from(item)
        else -> throw FormatException("can't convert to BossStruct: $item")
    }
}

