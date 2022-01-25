package com.github.zhenwei.pkix.its.operator;

import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.pkix.its.ITSCertificate;
import java.io.OutputStream;

public interface ITSContentSigner {

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

  ITSCertificate getAssociatedCertificate();

  byte[] getAssociatedCertificateDigest();

  AlgorithmIdentifier getDigestAlgorithm();

  /**
   * Return true if this ContentSigner is for self signing. False otherwise.
   *
   * @return true if for self-signing.
   */
  boolean isForSelfSigning();
}