import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.promise
import net.sergeych.unikrypto.withUnicrypto

@OptIn(DelicateCoroutinesApi::class)
actual fun runTest(block: suspend () -> Unit): dynamic = GlobalScope.promise {
    withUnicrypto { block() }
}


