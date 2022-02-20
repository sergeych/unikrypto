@file:Suppress("EXPERIMENTAL_API_USAGE")

package net.sergeych.unikrypto

import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import net.sergeych.mp_logger.LogTag
import net.sergeych.mp_logger.info

/**
 * Fabric to create and buffer private keys in background. This is ofyen a good idea to have a ready
 * key when one needs it. Note that ahead key generator does not starts automatically, use [start]
 * to run it.
 * @param bitStrength key bit strength of the generated keys
 * @param bufferSize how many ready keys to kee ready in buffer
 */
@Suppress("unused")
class AheadPrivateKeyGenerator(val bitStrength: Int, bufferSize: Int) : LogTag("AKGEN") {

    private val channel = Channel<Deferred<PrivateKey>>(bufferSize)
    private val mutex = Mutex()
    private var generatorStarted = false

    /**
     * Start generating private keys in the background, trying to buffer number keys specified in the constructor.
     * Use [getKey] to retrieve buffered keys. Note that the generating suspends when required number of keys are
     * created and buffered, and resumes when [getKey] is called.
     */
    fun start() {
        GlobalScope.launch {
            mutex.withLock {
                if (!generatorStarted) {
                    generatorStarted = true
                    while (isActive) {
                        // We ant exacly 2 generated keys in buffer, no more, so we put ot first to the
                        // channel (that will block until there is space in that buffer):
                        val d = CompletableDeferred<PrivateKey>()
                        channel.send(d)
                        // and now we will calculate the key separately (as generator uses another kernel or worker
                        // thread and can happily run in parallel!)
                        info { "start gnerating new key" }
                        launch { d.complete(AsymmetricKeys.generate(bitStrength)) }
                    }
                }
            }
        }
    }

    /**
     * get the next key, starting generator if need. Suspend until a key will be available, e.g. if there is buffered
     * key, returns it immediately. Retrieving key always makes generator creating new key in the background.
     */
    suspend fun getKey(): PrivateKey {
        if (!generatorStarted) start()
        return channel.receive().await()
    }
}