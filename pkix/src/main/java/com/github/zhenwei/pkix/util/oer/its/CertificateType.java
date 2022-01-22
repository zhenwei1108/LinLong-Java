package com.github.zhenwei.pkix.util.oer.its;

import ASN1Enumerated;
import java.math.BigInteger;

/**
 * CertificateType ::= ENUMERATED {
 * explicit,
 * implicit,
 * ...
 * }
 */
public class CertificateType
    extends ASN1Enumerated
{
    public static final CertificateType Explicit = new CertificateType(0);
    public static final CertificateType Implicit = new CertificateType(1);

    protected CertificateType(int ordinal)
    {
        super(ordinal);
    }

    public static CertificateType getInstance(Object src)
    {
        if (src instanceof CertificateType)
        {
            return (CertificateType)src;
        }
        else
        {
            BigInteger bi = ASN1Enumerated.getInstance(src).getValue();
            switch (bi.intValue())
            {
            case 0:
                return Explicit;
            case 1:
                return Implicit;
            default:
                throw new IllegalArgumentException("unaccounted enum value " + bi);
            }
        }
    }

}