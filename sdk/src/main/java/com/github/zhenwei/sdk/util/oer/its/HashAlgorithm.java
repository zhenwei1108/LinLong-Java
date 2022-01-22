package com.github.zhenwei.sdk.util.oer.its;

import ASN1Enumerated;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;


/**
 * CertificateType ::= ENUMERATED {
 * explicit,
 * implicit,
 * ...
 * }
 */
public class HashAlgorithm
    extends ASN1Object
{

    public static final HashAlgorithm sha256 = new HashAlgorithm(0);
    public static final HashAlgorithm sha384 = new HashAlgorithm(1);
    public static final HashAlgorithm extension = new HashAlgorithm(2);

    private final ASN1Enumerated enumerated;

    protected HashAlgorithm(int ordinal)
    {
        enumerated = new ASN1Enumerated(ordinal);
    }

    private HashAlgorithm(ASN1Enumerated enumerated)
    {
        this.enumerated = enumerated;
    }

    public static HashAlgorithm getInstance(Object src)
    {
        if (src == null)
        {
            return null;
        }
        else if (src instanceof HashAlgorithm)
        {
            return (HashAlgorithm)src;
        }
        else
        {
            return new HashAlgorithm(ASN1Enumerated.getInstance(src));
        }
    }

    public ASN1Primitive toASN1Primitive()
    {
        return enumerated;
    }
}