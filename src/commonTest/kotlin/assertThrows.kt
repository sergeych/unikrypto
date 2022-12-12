import kotlin.test.fail

inline fun <reified T: Throwable>assertThrows(f: ()->Unit): T {
    try {
        f()
        fail("expected exception of type ${T::class.simpleName} has not been thrown")
    }
    catch(ex: Throwable) {
        if( ex is T)
            return ex
        fail("expected exception of type ${T::class.simpleName} got ${ex::class.simpleName}: $ex")
    }
}
