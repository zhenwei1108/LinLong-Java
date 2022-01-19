package com.github.zhenwei.sdk.util.asn1.cmc;

import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 * <pre>
 * CMCFailInfo ::= INTEGER {
 *     badAlg          (0),
 *     badMessageCheck (1),
 *     badRequest      (2),
 *     badTime         (3),
 *     badCertId       (4),
 *     unsupportedExt  (5),
 *     mustArchiveKeys (6),
 *     badIdentity     (7),
 *     popRequired     (8),
 *     popFailed       (9),
 *     noKeyReuse      (10),
 *     internalCAError (11),
 *     tryLater        (12),
 *     authDataFail    (13)
 * }
 * </pre>
 */
public class CMCFailInfo
    extends ASN1Object
{
    public static final org.bouncycastle.asn1.cmc.CMCFailInfo badAlg = new org.bouncycastle.asn1.cmc.CMCFailInfo(new ASN1Integer(0));
    public static final org.bouncycastle.asn1.cmc.CMCFailInfo badMessageCheck = new org.bouncycastle.asn1.cmc.CMCFailInfo(new ASN1Integer(1));
    public static final org.bouncycastle.asn1.cmc.CMCFailInfo badRequest = new org.bouncycastle.asn1.cmc.CMCFailInfo(new ASN1Integer(2));
    public static final org.bouncycastle.asn1.cmc.CMCFailInfo badTime = new org.bouncycastle.asn1.cmc.CMCFailInfo(new ASN1Integer(3));
    public static final org.bouncycastle.asn1.cmc.CMCFailInfo badCertId = new org.bouncycastle.asn1.cmc.CMCFailInfo(new ASN1Integer(4));
    public static final org.bouncycastle.asn1.cmc.CMCFailInfo unsupportedExt = new org.bouncycastle.asn1.cmc.CMCFailInfo(new ASN1Integer(5));
    public static final org.bouncycastle.asn1.cmc.CMCFailInfo mustArchiveKeys = new org.bouncycastle.asn1.cmc.CMCFailInfo(new ASN1Integer(6));
    public static final org.bouncycastle.asn1.cmc.CMCFailInfo badIdentity = new org.bouncycastle.asn1.cmc.CMCFailInfo(new ASN1Integer(7));
    public static final org.bouncycastle.asn1.cmc.CMCFailInfo popRequired = new org.bouncycastle.asn1.cmc.CMCFailInfo(new ASN1Integer(8));
    public static final org.bouncycastle.asn1.cmc.CMCFailInfo popFailed = new org.bouncycastle.asn1.cmc.CMCFailInfo(new ASN1Integer(9));
    public static final org.bouncycastle.asn1.cmc.CMCFailInfo noKeyReuse = new org.bouncycastle.asn1.cmc.CMCFailInfo(new ASN1Integer(10));
    public static final org.bouncycastle.asn1.cmc.CMCFailInfo internalCAError = new org.bouncycastle.asn1.cmc.CMCFailInfo(new ASN1Integer(11));
    public static final org.bouncycastle.asn1.cmc.CMCFailInfo tryLater = new org.bouncycastle.asn1.cmc.CMCFailInfo(new ASN1Integer(12));
    public static final org.bouncycastle.asn1.cmc.CMCFailInfo authDataFail = new org.bouncycastle.asn1.cmc.CMCFailInfo(new ASN1Integer(13));

    private static Map range = new HashMap();

    static
    {
        range.put(badAlg.value, badAlg);
        range.put(badMessageCheck.value, badMessageCheck);
        range.put(badRequest.value, badRequest);
        range.put(badTime.value, badTime);
        range.put(badCertId.value, badCertId);
        range.put(popRequired.value, popRequired);
        range.put(unsupportedExt.value, unsupportedExt);
        range.put(mustArchiveKeys.value, mustArchiveKeys);
        range.put(badIdentity.value, badIdentity);
        range.put(popRequired.value, popRequired);
        range.put(popFailed.value, popFailed);
        range.put(badCertId.value, badCertId);
        range.put(popRequired.value, popRequired);
        range.put(noKeyReuse.value, noKeyReuse);
        range.put(internalCAError.value, internalCAError);
        range.put(tryLater.value, tryLater);
        range.put(authDataFail.value, authDataFail);
    }

    private final ASN1Integer value;

    private CMCFailInfo(ASN1Integer value)
    {
         this.value = value;
    }

    public static org.bouncycastle.asn1.cmc.CMCFailInfo getInstance(Object o)
    {
        if (o instanceof org.bouncycastle.asn1.cmc.CMCFailInfo)
        {
            return (org.bouncycastle.asn1.cmc.CMCFailInfo)o;
        }

        if (o != null)
        {
            org.bouncycastle.asn1.cmc.CMCFailInfo status = (org.bouncycastle.asn1.cmc.CMCFailInfo)range.get(ASN1Integer.getInstance(o));

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