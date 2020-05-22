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
package okhttp.android.test.compare;

import androidx.test.ext.junit.runners.AndroidJUnit4
import okhttp3.CertificatePinner
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import javax.net.ssl.SSLPeerUnverifiedException

/**
 * OkHttp.
 *
 * https://square.github.io/okhttp/
 */
@RunWith(AndroidJUnit4::class)
class OkHttpClientTest {
  val pinner = CertificatePinner.Builder()
      .add(
          "google.com",
          "sha256/iie1VXtL7HzAMF+/PVPR9xzT80kQxdZeJ+zduCB3uj0="
      )
      .add(
          "facebook.com",
          "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
      )
      .build()

  val client = OkHttpClient.Builder()
      .certificatePinner(pinner)
      .build()

  @Test fun certificatePinningWorks() {
    val request = Request.Builder()
        .url("https://google.com/robots.txt")
        .build()
    client.newCall(request).execute().use { response ->
      println(response.code())
    }
  }

  @Test fun certificatePinningFails() {
    val request = Request.Builder()
        .url("https://facebook.com/robots.txt")
        .build()
    try {
      client.newCall(request)
          .execute()
          .use { response ->
            println(response.code())
          }

      fail()
    } catch (spe: SSLPeerUnverifiedException) {
      // expected
    }
  }
}
