package com.github.zhenwei.pkix.eac.operator;

import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import java.io.OutputStream;

public interface EACSigner {

  ASN1ObjectIdentifier getUsageIdentifier();

  /**
   * Returns a stream that will accept data for the purpose of calculating a signature. Use
   * com.github.zhenwei.core.util.io.TeeOutputStream if you want to accumulate the data on the fly
   * as well.
   *
   * @return an OutputStream
   */
  OutputStream getOutputStream();

  /**
   * Returns a signature based on the current data written to the stream, since the start or the
   * last call to getSignature().
   *
   * @return bytes representing the signature.
   */
  byte[] getSignature();
}