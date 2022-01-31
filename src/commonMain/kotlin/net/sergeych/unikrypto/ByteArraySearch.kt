@file:OptIn(ExperimentalUnsignedTypes::class)
@file:Suppress("unused")

package net.sergeych.unikrypto

import kotlin.math.max

/**
 * Find first occurrence of a binary substring in this binary array. Uses fast Boyer-Moore algorithm.
 */
fun ByteArray.indexOf(needle: ByteArray) = indexOf(toUByteArray(), needle.toUByteArray())

/**
 * Find first occurrence of a binary substring in this binary array. Uses fast Boyer-Moore algorithm.
 */
fun ByteArray.indexOf(needle: String) = indexOf(toUByteArray(), needle.encodeToByteArray().toUByteArray())

/**
 * Returns the index within this string of the first occurrence of the
 * specified substring. If it is not a substring, return -1.
 *
 * There is no Galil because it only generates one match.
 *
 * @param haystack The string to be scanned
 * @param needle The target string to search
 * @return The start index of the substring
 */
private fun indexOf(haystack: UByteArray, needle: UByteArray): Int {
    if (needle.size == 0) {
        return 0
    }
    val charTable = makeCharTable(needle)
    val offsetTable = makeOffsetTable(needle)
    var i = needle.size - 1
    var j: Int
    while (i < haystack.size) {
        j = needle.size - 1
        while (needle[j] == haystack[i]) {
            if (j == 0) {
                return i
            }
            --i
            --j
        }
        // i += needle.length - j; // For naive method
        i += max(offsetTable[needle.size - 1 - j], charTable[haystack[i].toInt()])
    }
    return -1
}

/**
 * Makes the jump table based on the mismatched character information.
 */
private fun makeCharTable(needle: UByteArray): IntArray {
    val ALPHABET_SIZE: Int = UByte.MAX_VALUE.toInt() + 1
    val table = IntArray(ALPHABET_SIZE)
    for (i in table.indices) {
        table[i] = needle.size
    }
    for (i in needle.indices) {
        table[needle[i].toInt()] = needle.size - 1 - i
    }
    return table
}

/**
 * Makes the jump table based on the scan offset which mismatch occurs.
 * (bad character rule).
 */
private fun makeOffsetTable(needle: UByteArray): IntArray {
    val table = IntArray(needle.size)
    var lastPrefixPosition = needle.size
    for (i in needle.size downTo 1) {
        if (isPrefix(needle, i)) {
            lastPrefixPosition = i
        }
        table[needle.size - i] = lastPrefixPosition - i + needle.size
    }
    for (i in 0 until needle.size - 1) {
        val slen = suffixLength(needle, i)
        table[slen] = needle.size - 1 - i + slen
    }
    return table
}

/**
 * Is needle[p:end] a prefix of needle?
 */
private fun isPrefix(needle: UByteArray, p: Int): Boolean {
    var i = p
    var j = 0
    while (i < needle.size) {
        if (needle[i] != needle[j]) {
            return false
        }
        ++i
        ++j
    }
    return true
}

/**
 * Returns the maximum length of the substring ends at p and is a suffix.
 * (good suffix rule)
 */
private fun suffixLength(needle: UByteArray, p: Int): Int {
    var len = 0
    var i = p
    var j = needle.size - 1
    while (i >= 0 && needle[i] == needle[j]) {
        len += 1
        --i
        --j
    }
    return len
}