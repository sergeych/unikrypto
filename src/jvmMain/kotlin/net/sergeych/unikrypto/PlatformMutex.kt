package net.sergeych.unikrypto

actual fun PlatformMutex(): GenericMutex = object : GenericMutex {
    override fun <T> withLock(block: () -> T): T = synchronized(this) { block() }
}