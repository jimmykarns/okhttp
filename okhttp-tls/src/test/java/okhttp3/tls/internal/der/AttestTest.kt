/*
 * Copyright (C) 2020 Square, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package okhttp3.tls.internal.der

import okhttp3.tls.decodeCertificatePem
import okio.ByteString
import okio.ByteString.Companion.decodeBase64
import okio.ByteString.Companion.decodeHex
import okio.ByteString.Companion.encodeUtf8
import okio.ByteString.Companion.toByteString
import org.assertj.core.api.Assertions.assertThat
import org.junit.Test

internal class AttestTest {
  @Test
  fun `decode attestation certificate`() {
    val certificateBase64 = """
        |MIIENDCCAxygAwIBAgIBATANBgkqhkiG9w0BAQsFADAvMRkwFwYDVQQFExA5MGU4
        |ZGEzY2FkZmM3ODIwMRIwEAYDVQQMDAlTdHJvbmdCb3gwHhcNNjUxMTIwMjMyNTI3
        |WhcNMjgwNTIzMjM1OTU5WjAfMR0wGwYDVQQDDBRBbmRyb2lkIEtleXN0b3JlIEtl
        |eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPWcYCbES7xkRgd40Ccq
        |opnWH1ZsrhuvAhEuvzyz0IJLmimG0Ntjg/xygnvvK/P/dJ0HlhRbt3sKPn1sFoF7
        |JmkviYtOGBexVpliCub0sHdpznxrPjXNZkbHhrzERx1HwT/rzfCqgyrrfW6JxBKy
        |SpV73xkIftslaBVfGhlSYGJjmD8Q5CsqfhTTWWvrY3nmHH5/Db+YnBvMboDKEIjf
        |HorIOA4RImZG3oyb4U82C34XF0vkIrY+4MSkhwi37AQM7439KUDgvL7ALzXHd2iq
        |RROyVNcUHI3i+avzS7BfisO+1pIf9Vo2TNhyPJqjph/JvNx8VMZDa2QCGNXLuo1B
        |gncCAwEAAaOCAWkwggFlMA4GA1UdDwEB/wQEAwIHgDCCAVEGCisGAQQB1nkCAREE
        |ggFBMIIBPQIBBAoBAgIBKQoBAgQgWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZ
        |WVlZWVkEADBZv4U9CAIGAXMDyOtnv4VFSQRHMEUxHzAdBBhva2h0dHAuYW5kcm9p
        |ZC50ZXN0LnRlc3QCAQAxIgQg+6U5SxIKm5G+wXi0mkOJvG24tElFRIy63EA/gsjo
        |3kQwga+hCDEGAgECAgEDogMCAQGjBAICCAClBTEDAgEEpgUxAwIBBb+BSAUCAwEA
        |Ab+DdwIFAL+FPgMCAQC/hUBMMEoEIK5jFrR1PGH1hVuVubmEhK94Ty6DZI0PzIEH
        |/KdSyuo0AQH/CgEABCA3qY0bowmRk47RgZh+4m+Lk8Rbe9kbPtsr+W4VvuF5lL+F
        |QQUCAwGtsL+FQgUCAwMVFr+FTgYCBAE0PJ2/hU8GAgQBNDydMA0GCSqGSIb3DQEB
        |CwUAA4IBAQAWhB8/kQnNVjsVJIy0whdhWtFBhoEoH3LCRtYjn8zm7N6zOgfp/+Ml
        |pMzf60Ikh/rJISScEy5VGA/KW6FQG0urK2bY0ukkq9+wU+nW6sIeHjKDfLM86Z/R
        |PZ3kjv06h6Qoubm5JSqikb+j49ACg5lZOm1w2NqI/LIKNmw/lYlIXgLEPKz/IwMN
        |2qUeHz9otIHOrjED8BuWpIfGQKHSyESs72DzsPMVc7wG50JJMwkGsmLYXIfxwc97
        |XLsDFj3438TbZBotk+SB0zR4S/cAhv1NxglvfTaZmCX76gG1567k+J3JrTdhosId
        |ErH4Tiob1bCBMtaIT6am/DfUaMqG2Ye5
        |""".trimMargin()
    val certificateByteString = certificateBase64.decodeBase64()!!
    val certificatePem = """
        |-----BEGIN CERTIFICATE-----
        |$certificateBase64
        |-----END CERTIFICATE-----
        |""".trimMargin()

    val javaCertificate = certificatePem.decodeCertificatePem()
    val okHttpCertificate = CertificateAdapters.certificate
        .fromDer(certificateByteString)

    assertThat(okHttpCertificate.signatureValue.byteString)
        .isEqualTo(javaCertificate.signature.toByteString())

    val keyDescription = okHttpCertificate.tbsCertificate.extensions.first {
      it.id == AttestationAdapters.KEY_DESCRIPTION_OID
    }.value as KeyDescription

    assertThat(keyDescription).isEqualTo(
        KeyDescription(
            attestationVersion = 4L,
            attestationSecurityLevel = 2L, // 2=StrongBox
            keymasterVersion = 41L,
            keymasterSecurityLevel = 2L, // 2=StrongBox
            attestationChallenge = "YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY".encodeUtf8(),
            uniqueId = ByteString.EMPTY,
            softwareEnforced = AuthorizationList(
                creationDateTime = 1593496365927L,
                attestationApplicationId = "3045311f301d04186f6b687474702e616e64726f69642e746573742e7465737402010031220420fba5394b120a9b91bec178b49a4389bc6db8b44945448cbadc403f82c8e8de44".decodeHex()
            ),
            teeEnforced = AuthorizationList(
                purpose = listOf(2L, 3L),
                algorithm = 1L,
                keySize = 2048L,
                digest = listOf(4L),
                padding = listOf(5L),
                rsaPublicExponent = 65537L,
                origin = 0,
                rootOfTrust = RootOfTrust(
                    verifiedBootKey = "ae6316b4753c61f5855b95b9b98484af784f2e83648d0fcc8107fca752caea34".decodeHex(),
                    deviceLocked = true,
                    verifiedBootState = 0L, // 0=Verified.
                    verifiedBootHash = "37a98d1ba30991938ed181987ee26f8b93c45b7bd91b3edb2bf96e15bee17994".decodeHex()
                ),
                osVersion = 110000L,
                osPatchLevel = 202006L,
                vendorPatchLevel = 20200605L,
                bootPatchLevel = 20200605L
            )
        )
    )
  }
}
