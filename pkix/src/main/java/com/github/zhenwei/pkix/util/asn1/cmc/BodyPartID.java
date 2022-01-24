package com.github.zhenwei.pkix.util.asn1.cmc;

import java.math.BigInteger;
import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;

/**
 * <pre>
 *       bodyIdMax INTEGER ::= 4294967295
 *
 *       BodyPartID ::= INTEGER(0..bodyIdMax)
 * </pre>
 */
public class BodyPartID
    extends ASN1Object
{
    public static final long bodyIdMax = 4294967295L;

    private final long id;

    public BodyPartID(long id)
    {
        if (id < 0 || id > bodyIdMax)
        {
            throw new IllegalArgumentException("id out of range");
        }

        this.id = id;
    }

    private static long convert(BigInteger value)
    {
        if (value.bitLength() > 32)
        {
            throw new IllegalArgumentException("id out of range");
        }
        return value.longValue();
    }

    private BodyPartID(ASN1Integer id)
    {
        this(convert(id.getValue()));
    }

    public static BodyPartID getInstance(Object o)
    {
        if (o instanceof BodyPartID)
        {
            return (BodyPartID)o;
        }

        if (o != null)
        {
            return new BodyPartID(ASN1Integer.getInstance(o));
        }

        return null;
    }

    public long getID()
    {
        return id;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new ASN1Integer(id);
    }
}