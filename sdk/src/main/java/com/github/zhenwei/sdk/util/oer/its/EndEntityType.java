package com.github.zhenwei.sdk.util.oer.its;


import com.github.zhenwei.core.asn1.ASN1BitString;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.DERBitString;

/**
 * <pre>
 *     EndEntityType ::= BIT STRING { app(0), enrol(1) } (SIZE (8)) (ALL EXCEPT ())
 * </pre>
 */
public class EndEntityType
    extends ASN1Object
{
    public static final int app = (1 << 7);
    public static final int enrol = (1 << 6);

    private final ASN1BitString type;

    public EndEntityType(int eeType)
    {
        this(new DERBitString(eeType));
    }


    public EndEntityType(DERBitString str)
    {
        this.type = str;
    }

    public static EndEntityType getInstance(Object src)
    {
        if (src instanceof EndEntityType)
        {
            return (EndEntityType)src;
        }
        else if (src != null)
        {
            return new EndEntityType(DERBitString.getInstance(src));
        }

        return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return type;
    }
}