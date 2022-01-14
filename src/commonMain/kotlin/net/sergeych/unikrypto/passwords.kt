package net.sergeych.unikrypto

import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.math.log2
import kotlin.random.Random

object Passwords {

    private class CharacterClass(source: String) {
        val chars = source.toSet()
        val strength: Double = log2(chars.size.toDouble())
    }

    private val downLetters = "qwertyuiopasdfghjklzxcvbnm"

    private val characterClasses = arrayOf(
        downLetters, downLetters.uppercase(),
        "1234567890",
        "_-+=!@#$%^&*()?/<>,."  // frequent puctuation
    ).map(::CharacterClass)

    private val dupesRe = "(.)\\1+".toRegex()
    private fun removeDupes(str: String) = str.replace(dupesRe, "$1")

    /**
     * Estimate password for roughly equivalent entropy bits in the brute-force attack
     * model. Does not understand pattern- and vocabulary type weakness, only character set
     * variance. We recommend password with AT LEAST 128 bits estimated strength, better 200+.
     *
     * The strength critically depends on the variation of characters: better use all of:
     * punctuation, small letters, big letters, digits. National characters also improves
     * the picture, but better stick to latin1 set.
     */
    @Suppress("unused")
    fun estimateBitStrength(password: String): Int {
        val pwd = removeDupes(password.trim())
        val usedClasses = HashSet<CharacterClass>()
        var nonClassifiedChars = false
        for (ch in pwd) {
            var classFound = false
            for (cc in characterClasses) {
                if (cc.chars.contains(ch)) {
                    usedClasses.add(cc)
                    classFound = true
                    break
                }
            }
            if (!classFound) nonClassifiedChars = true
        }
        var totalBits = usedClasses.map { x -> x.strength }.sum()
        if (nonClassifiedChars) totalBits += 5
        return (totalBits * pwd.length).toInt()
    }

    enum class KeyIdAlgorithm {
        MyoCloud,
        Independent
    }

    /**
     * Derive several cryptographically strong and independent keys from the same password (assuming the password is strong).
     * Important! Do not change default value of [keyIdAlgorithm] unless you exactly know you need it.
     *
     * The derived PBKDF data is always 32 bytes longer that requested key space, last 32 bytes are used to
     * produce secure key ids (depending on `keyIdAlgorithm`, directly or independently for each key).
     */
    suspend fun deriveKeys(
        password: String,
        amount: Int,
        rounds: Int,
        algorithm: HashAlgorithm = HashAlgorithm.SHA3_256,
        salt: ByteArray = Random.nextBytes(32),
        keyIdAlgorithm: KeyIdAlgorithm = KeyIdAlgorithm.Independent,
    ): List<SymmetricKey> =
        Generator.generate(password, amount, salt, algorithm, rounds, keyIdAlgorithm)


    /**
     * PBKDF generated spaces are cached in memory; to enforce more security against spectr-type cache attacks
     * it is a good idea to clear the cache when not needed.
     */
    @Suppress("unused")
    suspend fun clearPasswordsCache() {
        Generator.clearCache()
    }

    internal class Generator private constructor(
        val rawBytes: ByteArray,
        val hashAlgorithm: HashAlgorithm,
        val seed: ByteArray,
        val rounds: Int
    ) {

        val idPart = rawBytes.sliceArray((rawBytes.size - 32) until rawBytes.size)

        suspend fun buildKey(
            from: Int, length: Int,
            idAlgorithm: KeyIdAlgorithm = KeyIdAlgorithm.Independent
        ): SymmetricKey {
            val idBytes = when (idAlgorithm) {
                KeyIdAlgorithm.Independent ->
                    HashAlgorithm.SHA3_256.digest(idPart + "$from:$length".encodeToByteArray())
                KeyIdAlgorithm.MyoCloud -> idPart
            }
            return SymmetricKeys.create(
                rawBytes.sliceArray(from until (from + length)),
                PasswordId(idBytes, hashAlgorithm, rounds, length, from, rawBytes.size, seed)
            )
        }

        suspend fun buildKeys(idAlgorithm: KeyIdAlgorithm): List<SymmetricKey> {
            val amount = (rawBytes.size - 32) / 32
            var offset = 0
            return (0 until amount).map {
                buildKey(offset, 32, idAlgorithm).also { offset += 32 }
            }
        }

        /**
         * Fill the data with randoms. Use it only when ths instance will never be used again as a bait
         * for key-stealer specter-like attacks.
         */
        private fun clear() {
            Random.nextBytes(rawBytes)
        }

        companion object {

            private val cache = mutableMapOf<String, Deferred<Generator>>()
            private val access = Mutex()

            /**
             * Clears the generated PBKDF space cache. Next PBKDF will guarateed to fire slow generation
             * again. Data are wiped with some care.
             */
            suspend fun clearCache() {
                access.withLock {
                    for (g in cache.values) g.await().clear()
                    cache.clear()
                }
            }

            /**
             * Generage a single key from possibly multikey PBKDF space
             */
            suspend fun generateKey(password: String, passwordId: PasswordId) = generator(
                password,
                passwordId.generatedLength,
                passwordId.hashAlgorithm,
                passwordId.rounds,
                passwordId.seed
            ).buildKey(passwordId.keyOffseet, passwordId.keyLength)

            suspend fun generate(
                password: String,
                amount: Int,
                seed: ByteArray,
                algorithm: HashAlgorithm,
                rounds: Int,
                idAlgorithm: KeyIdAlgorithm = KeyIdAlgorithm.Independent
            ): List<SymmetricKey> {
                val length = amount * 32 + 32
                return generator(password, length, algorithm, rounds, seed).buildKeys(idAlgorithm)
            }

            private suspend fun generator(
                password: String,
                length: Int,
                algorithm: HashAlgorithm,
                rounds: Int,
                seed: ByteArray
            ): Generator {
                val passwordKeyHash = HashAlgorithm.SHA3_256.digest(password).encodeToHex()
                val key = "$passwordKeyHash:${seed.encodeToHex()}:${algorithm.ordinal}:$rounds:$length"
                return access.withLock {
                    cache.getOrPut(key) {
                        coroutineScope {
                            async {
                                Generator(
                                    PerformPBKDF2(
                                        password,
                                        length,
                                        algorithm,
                                        rounds,
                                        seed
                                    ),
                                    algorithm,
                                    seed,
                                    rounds
                                )
                            }
                        }
                    }
                }.await()
            }
        }
    }
}
