package com.github.zhenwei.sdk.util.asn1.cmc;


import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import java.util.HashMap;
import java.util.Map;

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
    public static final cmc.CMCStatus success = new cmc.CMCStatus(new ASN1Integer(0));
    public static final cmc.CMCStatus failed = new cmc.CMCStatus(new ASN1Integer(2));
    public static final cmc.CMCStatus pending = new cmc.CMCStatus(new ASN1Integer(3));
    public static final cmc.CMCStatus noSupport = new cmc.CMCStatus(new ASN1Integer(4));
    public static final cmc.CMCStatus confirmRequired = new cmc.CMCStatus(new ASN1Integer(5));
    public static final cmc.CMCStatus popRequired = new cmc.CMCStatus(new ASN1Integer(6));
    public static final cmc.CMCStatus partial = new cmc.CMCStatus(new ASN1Integer(7));

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

    public static cmc.CMCStatus getInstance(Object o)
    {
        if (o instanceof cmc.CMCStatus)
        {
            return (cmc.CMCStatus)o;
        }

        if (o != null)
        {
            cmc.CMCStatus status = (cmc.CMCStatus)range.get(ASN1Integer.getInstance(o));

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