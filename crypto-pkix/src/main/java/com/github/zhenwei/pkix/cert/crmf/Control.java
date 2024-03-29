package com.github.zhenwei.pkix.cert.crmf;

import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;

/**
 * Generic interface for a CertificateRequestMessage control value.
 */
public interface Control {

  /**
   * Return the type of this control.
   *
   * @return an ASN1ObjectIdentifier representing the type.
   */
  ASN1ObjectIdentifier getType();

  /**
   * Return the value contained in this control object.
   *
   * @return the value of the control.
   */
  ASN1Encodable getValue();
}