package net.sergeych.unikrypto

import net.sergeych.mp_tools.globalLaunch

/**
 * When writing for JS / MP, it is needed to synchronously initialize the library
 * as it loads wasm module with actual cryptography. It is safe to call it many times.
 * Ee recommend to do it early with [StartUnikrypto]
 */
expect suspend fun InitUnicrypto()

/**
 * Start initializatino of the unikrypto library (e.g. loading and initializing the wasm module) in
 * a separate coroutine. Useful to start it early.
 */
fun StartUnikrypto() { globalLaunch { InitUnicrypto() } }

/**
 * Perform block when unikrypto library is ready and return its result.
 */
expect suspend fun <T>withUnicrypto(block: suspend ()->T): T