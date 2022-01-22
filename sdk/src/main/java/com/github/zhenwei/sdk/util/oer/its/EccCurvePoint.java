package com.github.zhenwei.sdk.util.oer.its;



/**
 * Common interface for ITS curve points.
 */
public abstract class EccCurvePoint
    extends ASN1Object
{
    public abstract byte[] getEncodedPoint();
}