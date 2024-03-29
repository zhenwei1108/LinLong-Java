package com.github.zhenwei.pkix.cert.cmp;

import com.github.zhenwei.core.asn1.ASN1Encoding;
import com.github.zhenwei.core.asn1.ASN1Object;
import java.io.IOException;
import java.io.OutputStream;

class CMPUtil {

  static void derEncodeToStream(ASN1Object obj, OutputStream stream) {
    try {
      obj.encodeTo(stream, ASN1Encoding.DER);
      stream.close();
    } catch (IOException e) {
      throw new CMPRuntimeException("unable to DER encode object: " + e.getMessage(), e);
    }
  }
}