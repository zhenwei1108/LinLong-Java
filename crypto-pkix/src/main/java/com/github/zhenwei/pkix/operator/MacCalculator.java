package com.github.zhenwei.pkix.operator;

import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import java.io.OutputStream;

/**
 * General interface for a key initialized operator that is able to calculate a MAC from a stream of
 * output.
 */
public interface MacCalculator {

  AlgorithmIdentifier getAlgorithmIdentifier();

  /**
   * Returns a stream that will accept data for the purpose of calculating the MAC for later
   * verification. Use com.github.zhenwei.core.util.io.TeeOutputStream if you want to accumulate the
   * data on the fly as well.
   *
   * @return an OutputStream
   */
  OutputStream getOutputStream();

  /**
   * Return the calculated MAC based on what has been written to the stream.
   *
   * @return calculated MAC.
   */
  byte[] getMac();


  /**
   * Return the key used for calculating the MAC.
   *
   * @return the MAC key.
   */
  GenericKey getKey();
}