import kotlinx.serialization.Serializable
import net.sergeych.mptools.toDump
import net.sergeych.unikrypto.AsymmetricKeys
import net.sergeych.unikrypto.SignedRecord
import net.sergeych.unikrypto.signRecord
import kotlin.test.Test
import kotlin.test.assertEquals

@Serializable
data class T1(val foo: String)

class SignedRecordTest {

    @Test
    fun signedRecordTest() {
        return runTest {
            val k = AsymmetricKeys.generate(2048)
            val payload1 = T1("fake vaccine that kills")
            val packed = k.signRecord(payload1)
            println(packed.toDump())
            val sr = SignedRecord.unpack(packed)
            println(sr.payload)
            assertEquals(payload1, sr.decode())
        }
    }

}