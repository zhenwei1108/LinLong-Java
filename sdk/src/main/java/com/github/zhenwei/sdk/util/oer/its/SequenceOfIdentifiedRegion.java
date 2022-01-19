package com.github.zhenwei.sdk.util.oer.its;

import java.util.Collections;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class SequenceOfIdentifiedRegion
    extends ASN1Object
{

    private final List<IdentifiedRegion> identifiedRegions;


    public SequenceOfIdentifiedRegion(List<IdentifiedRegion> identifiedRegions)
    {
        this.identifiedRegions = Collections.unmodifiableList(identifiedRegions);
    }

    public static SequenceOfIdentifiedRegion getInstance(Object o)
    {
        if (o instanceof SequenceOfIdentifiedRegion)
        {
            return (SequenceOfIdentifiedRegion)o;
        }

        return new SequenceOfIdentifiedRegion(Utils.fillList(IdentifiedRegion.class, ASN1Sequence.getInstance(o)));
    }

    public List<IdentifiedRegion> getIdentifiedRegions()
    {
        return identifiedRegions;
    }


    @Override
    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(identifiedRegions.toArray(new ASN1Encodable[0]));
    }
}