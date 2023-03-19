package net.sergeych.unikrypto

actual suspend fun InitUnicrypto() {
    // no special initialization needed
}

actual suspend fun <T> withUnicrypto(block: suspend () -> T): T {
    // no special initialization needed
    return block()
}