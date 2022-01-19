package com.github.zhenwei.core.asn1;

import java.util.Date;
import org.bouncycastle.asn1.ASN1UTCTime;

/**
 * DER UTC time object.
 */
public class DERUTCTime
    extends ASN1UTCTime
{
    DERUTCTime(byte[] bytes)
    {
        super(bytes);
    }

    public DERUTCTime(Date time)
    {
        super(time);
    }

    public DERUTCTime(String time)
    {
        super(time);
    }

    // TODO: create proper DER encoding.
}