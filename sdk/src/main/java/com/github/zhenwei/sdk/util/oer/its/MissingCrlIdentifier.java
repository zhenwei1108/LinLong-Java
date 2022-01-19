package com.github.zhenwei.sdk.util.oer.its;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

/**
 * MissingCrlIdentifier ::= SEQUENCE {
 * cracaId    HashedId3,
 * crlSeries  CrlSeries,
 * ...
 * }
 */
public class MissingCrlIdentifier
    extends ASN1Object
{
    private final HashedId.HashedId3 cracaId;
    private final CrlSeries crlSeries;


    public MissingCrlIdentifier(HashedId.HashedId3 cracaId, CrlSeries crlSeries)
    {
        this.cracaId = cracaId;
        this.crlSeries = crlSeries;
    }

    public static MissingCrlIdentifier getInstance(Object src)
    {
        if (src instanceof MissingCrlIdentifier)
        {
            return (MissingCrlIdentifier)src;
        }
        ASN1Sequence seq = ASN1Sequence.getInstance(src);
        HashedId id = HashedId.getInstance(seq.getObjectAt(0));
        CrlSeries series = CrlSeries.getInstance(seq.getObjectAt(1));

        return new MissingCrlIdentifier((HashedId.HashedId3)id, series);
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return Utils.toSequence(cracaId, crlSeries);
    }


    public HashedId.HashedId3 getCracaId()
    {
        return cracaId;
    }

    public CrlSeries getCrlSeries()
    {
        return crlSeries;
    }
}