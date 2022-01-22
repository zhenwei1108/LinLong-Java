package com.github.zhenwei.pkix.util.asn1.cmc;


import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import java.util.HashMap;
import java.util.Map;

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
    public static final cmc.CMCFailInfo badAlg = new cmc.CMCFailInfo(new ASN1Integer(0));
    public static final cmc.CMCFailInfo badMessageCheck = new cmc.CMCFailInfo(new ASN1Integer(1));
    public static final cmc.CMCFailInfo badRequest = new cmc.CMCFailInfo(new ASN1Integer(2));
    public static final cmc.CMCFailInfo badTime = new cmc.CMCFailInfo(new ASN1Integer(3));
    public static final cmc.CMCFailInfo badCertId = new cmc.CMCFailInfo(new ASN1Integer(4));
    public static final cmc.CMCFailInfo unsupportedExt = new cmc.CMCFailInfo(new ASN1Integer(5));
    public static final cmc.CMCFailInfo mustArchiveKeys = new cmc.CMCFailInfo(new ASN1Integer(6));
    public static final cmc.CMCFailInfo badIdentity = new cmc.CMCFailInfo(new ASN1Integer(7));
    public static final cmc.CMCFailInfo popRequired = new cmc.CMCFailInfo(new ASN1Integer(8));
    public static final cmc.CMCFailInfo popFailed = new cmc.CMCFailInfo(new ASN1Integer(9));
    public static final cmc.CMCFailInfo noKeyReuse = new cmc.CMCFailInfo(new ASN1Integer(10));
    public static final cmc.CMCFailInfo internalCAError = new cmc.CMCFailInfo(new ASN1Integer(11));
    public static final cmc.CMCFailInfo tryLater = new cmc.CMCFailInfo(new ASN1Integer(12));
    public static final cmc.CMCFailInfo authDataFail = new cmc.CMCFailInfo(new ASN1Integer(13));

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

    public static cmc.CMCFailInfo getInstance(Object o)
    {
        if (o instanceof cmc.CMCFailInfo)
        {
            return (cmc.CMCFailInfo)o;
        }

        if (o != null)
        {
            cmc.CMCFailInfo status = (cmc.CMCFailInfo)range.get(ASN1Integer.getInstance(o));

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