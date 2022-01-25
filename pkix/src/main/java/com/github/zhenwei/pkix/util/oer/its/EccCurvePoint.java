package com.github.zhenwei.pkix.util.oer.its;

import com.github.zhenwei.core.asn1.ASN1Object;

/**
 * Common interface for ITS curve points.
 */
public abstract class EccCurvePoint
    extends ASN1Object {

  public abstract byte[] getEncodedPoint();
}