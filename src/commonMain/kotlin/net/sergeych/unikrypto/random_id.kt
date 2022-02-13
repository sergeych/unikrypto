package net.sergeych.unikrypto

import kotlin.random.Random

private val lowerLetters = "qwertyuiopasdfghjklzxcvbnm"
private val idFirstLetters = lowerLetters + lowerLetters.uppercase() + "_$"
private val idLetters = idFirstLetters + "1234567890-"

val CharSequence.sampleChar: Char
    get() = this[Random.nextInt(0,length)]

@Suppress("unused")
val <T> List<T>.sample: T
    get() = this[Random.nextInt(0,size)]

fun randomId(length: Int): String {
    if( length < 2 ) throw IllegalArgumentException("too short")
    val result = StringBuilder(idFirstLetters.sampleChar.toString())
    for( i in 1 until length ) result.append(idLetters.sampleChar)
    return result.toString()
}

