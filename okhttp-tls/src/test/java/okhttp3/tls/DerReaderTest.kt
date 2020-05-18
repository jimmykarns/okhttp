package okhttp3.tls

import okhttp3.internal.and
import okio.Buffer
import okio.BufferedSource
import org.assertj.core.api.Assertions.assertThat
import org.junit.Test
import java.math.BigInteger
import java.net.ProtocolException

class DerReaderTest {

  @Test fun tagAndLength() {
    val buffer = Buffer()
        .writeByte(0b00011110)
        .writeByte(0b10000001)
        .writeByte(0b11001001)

    val derReader = DerReader(buffer)


    assertThat(derReader.nextTag()).isEqualTo(0)
    assertThat(derReader.primitiveOrConstructed).isEqualTo(0)
    assertThat(derReader.tag).isEqualTo(30)
    assertThat(derReader.length).isEqualTo(201)
  }

  @Test
  fun happyPath() {
    val certificateString = """
      -----BEGIN CERTIFICATE-----
      MIIBmjCCAQOgAwIBAgIBATANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDEwhjYXNo
      LmFwcDAeFw03MDAxMDEwMDAwMDBaFw03MDAxMDEwMDAwMDFaMBMxETAPBgNVBAMT
      CGNhc2guYXBwMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCApFHhtrLan28q
      +oMolZuaTfWBA0V5aMIvq32BsloQu6LlvX1wJ4YEoUCjDlPOtpht7XLbUmBnbIzN
      89XK4UJVM6Sqp3K88Km8z7gMrdrfTom/274wL25fICR+yDEQ5fUVYBmJAKXZF1ao
      I0mIoEx0xFsQhIJ637v2MxJDupd61wIDAQABMA0GCSqGSIb3DQEBCwUAA4GBADam
      UVwKh5Ry7es3OxtY3IgQunPUoLc0Gw71gl9Z+7t2FJ5VkcI5gWfutmdxZ2bDXCI8
      8V0vxo1pHXnbBrnxhS/Z3TBerw8RyQqcaWOdp+pBXyIWmR+jHk9cHZCqQveTIBsY
      jaA9VEhgdaVhxBsT2qzUNDsXlOzGsliznDfoqETb
      -----END CERTIFICATE-----
      """.trimIndent()
  }

  /**
   * ASN.1: encoding
   * DER: distinguished rules to constrain ASN.1
   * BER: basic rules to constrain ASN.1
   *
   * Distinguished Encoding Rules (DER) as specified by X.690.
   *
   * https://www.itu.int/rec/T-REC-X.690
   *
   * Abstract Syntax Notation One (ASN.1)
   */
  class DerReader(val source: BufferedSource) {
    /** Bits 7,8. 00=Universal, 01=Application, 10=Context-Specific, 11=Private */
    var tagClass: Int = -1

    /** Bit 6. 0=Primitive, 1=Constructed */
    var primitiveOrConstructed: Int = -1

    /** TODO: is this tag plausible? */
    var tag: Long = -1L

    var length: Long = -1L

    fun nextTag(): Long {
      check(tagClass != -1) { "unexpected call to nextTag()" }

      // Read the tag.
      val tagAndClass = source.readByte().toInt() and 0xff
      tagClass = tagAndClass and 0b1100_0000
      primitiveOrConstructed = tagAndClass and 0b0010_0000
      val tag0 = tagAndClass and 0b0001_1111
      if (tag0 == 0b0001_1111) {
        var tagBits = 0L
        while (true) {
          val tagN = source.readByte()
              .toInt() and 0xff
          tagBits += (tagN and 0b0111_1111)
          if (tagN and 0b1000_0000 == 0b1000_0000) break
          tagBits = tagBits shl 7
        }
        tag = tagBits
      } else {
        tag = tag0.toLong()
      }

      // Read the length.
      val length0 = source.readByte()
          .toInt() and 0xff
      if (length0 == 0b1000_0000) {
        // Indefinite length.
        length = -1L
      } else if (length0 and 0b1000_0000 == 0b1000_0000) {
        // Length specified over multiple bytes.
        val lengthBytes = length0 and 0b0111_1111
        var lengthBits = source.readByte()
            .toLong() and 0xff
        for (i in 1 until lengthBytes) {
          lengthBits = lengthBits shl 8
          lengthBits += source.readByte()
              .toInt() and 0xff
        }
        length = lengthBits
      } else {
        // Length is 127 or fewer bytes.
        length = (length0 and 0b0111_1111).toLong()
      }

      return tag
    }

    fun readEndOfContents() {
      if (length != 0L) throw ProtocolException("unexpected length: $length")
      afterEncoding()
    }

    fun readBoolean(): Boolean {
      if (length != 1L) throw ProtocolException("unexpected length: $length")
      val result = source.readByte().toInt() != 0
      afterEncoding()
      return result
    }

    fun readBigInteger(): BigInteger {
      if (length == 0L) throw ProtocolException("unexpected length: $length")

      val byteArray = source.readByteArray(length)
      val result = BigInteger(byteArray)
      afterEncoding()
      return result
    }

    fun readLong(): Long {
      if (length !in 1..8) throw ProtocolException("unexpected length: $length")

      var result = source.readByte().toLong() // No "and 0xff" because this is a signed value.
      for (i in 1 until length) {
        result = result shl 8
        result += source.readByte().toInt() and 0xff
      }
      afterEncoding()
      return result
    }

    private fun afterEncoding() {
      tagClass = -1
      primitiveOrConstructed = -1
      tag = -1L
      length = -1L
    }

    companion object {
      val TAG_END_OF_CONTENTS = 0L
      val TAG_BOOLEAN = 1L
    }
  }
}
