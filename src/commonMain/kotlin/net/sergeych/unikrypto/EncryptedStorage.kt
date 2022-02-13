package net.sergeych.common

import net.sergeych.boss_serialization_mp.KVBinaryStorage
import net.sergeych.boss_serialization_mp.KVStorage
import net.sergeych.unikrypto.EncryptedBinaryStorage
import net.sergeych.unikrypto.SymmetricKey

/**
 * Construct encrypted storage using specified binary storage and encryption key
 */
@Suppress("unused")
fun EncryptedStorage(source: KVBinaryStorage, key: SymmetricKey) =
    KVStorage(EncryptedBinaryStorage(source, key))

