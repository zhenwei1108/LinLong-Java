package com.github.zhenwei.sdk.util.asn1.cmc;

import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * <pre>
 *
 * CMCStatus ::= INTEGER {
 *    success         (0),
 *    failed          (2),
 *    pending         (3),
 *    noSupport       (4),
 *    confirmRequired (5),
 *    popRequired     (6),
 *    partial         (7)
 * }
 * </pre>
 */
public class CMCStatus
    extends ASN1Object
{
    public static final org.bouncycastle.asn1.cmc.CMCStatus success = new org.bouncycastle.asn1.cmc.CMCStatus(new ASN1Integer(0));
    public static final org.bouncycastle.asn1.cmc.CMCStatus failed = new org.bouncycastle.asn1.cmc.CMCStatus(new ASN1Integer(2));
    public static final org.bouncycastle.asn1.cmc.CMCStatus pending = new org.bouncycastle.asn1.cmc.CMCStatus(new ASN1Integer(3));
    public static final org.bouncycastle.asn1.cmc.CMCStatus noSupport = new org.bouncycastle.asn1.cmc.CMCStatus(new ASN1Integer(4));
    public static final org.bouncycastle.asn1.cmc.CMCStatus confirmRequired = new org.bouncycastle.asn1.cmc.CMCStatus(new ASN1Integer(5));
    public static final org.bouncycastle.asn1.cmc.CMCStatus popRequired = new org.bouncycastle.asn1.cmc.CMCStatus(new ASN1Integer(6));
    public static final org.bouncycastle.asn1.cmc.CMCStatus partial = new org.bouncycastle.asn1.cmc.CMCStatus(new ASN1Integer(7));

    private static Map range = new HashMap();

    static
    {
        range.put(success.value, success);
        range.put(failed.value, failed);
        range.put(pending.value, pending);
        range.put(noSupport.value, noSupport);
        range.put(confirmRequired.value, confirmRequired);
        range.put(popRequired.value, popRequired);
        range.put(partial.value, partial);
    }

    private final ASN1Integer value;

    private CMCStatus(ASN1Integer value)
    {
         this.value = value;
    }

    public static org.bouncycastle.asn1.cmc.CMCStatus getInstance(Object o)
    {
        if (o instanceof org.bouncycastle.asn1.cmc.CMCStatus)
        {
            return (org.bouncycastle.asn1.cmc.CMCStatus)o;
        }

        if (o != null)
        {
            org.bouncycastle.asn1.cmc.CMCStatus status = (org.bouncycastle.asn1.cmc.CMCStatus)range.get(ASN1Integer.getInstance(o));

            if (status != null)
            {
                return status;
            }

            throw new IllegalArgumentException("unknown object in getInstance(): " + o.getClass().getName());
        }

        return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return value;
    }
}