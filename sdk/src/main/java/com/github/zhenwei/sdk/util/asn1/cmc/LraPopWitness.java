package com.github.zhenwei.sdk.util.asn1.cmc;


import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.DERSequence;

/**
 * <pre>
 * id-cmc-lraPOPWitness OBJECT IDENTIFIER ::= {id-cmc 11}
 *
 * LraPopWitness ::= SEQUENCE {
 *     pkiDataBodyid   BodyPartID,
 *     bodyIds         SEQUENCE OF BodyPartID
 * }
 * </pre>
 */
public class LraPopWitness
    extends ASN1Object
{
    private final BodyPartID pkiDataBodyid;
    private final ASN1Sequence bodyIds;

    public LraPopWitness(BodyPartID pkiDataBodyid, ASN1Sequence bodyIds)
    {
        this.pkiDataBodyid = pkiDataBodyid;
        this.bodyIds = bodyIds;
    }

    private LraPopWitness(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("incorrect sequence size");
        }
        this.pkiDataBodyid = BodyPartID.getInstance(seq.getObjectAt(0));
        this.bodyIds = ASN1Sequence.getInstance(seq.getObjectAt(1));
    }

    public static cmc.LraPopWitness getInstance(Object o)
    {
        if (o instanceof cmc.LraPopWitness)
        {
            return (cmc.LraPopWitness)o;
        }

        if (o != null)
        {
            return new cmc.LraPopWitness(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public BodyPartID getPkiDataBodyid()
    {
        return pkiDataBodyid;
    }


    public BodyPartID[] getBodyIds()
    {
        BodyPartID[] rv = new BodyPartID[bodyIds.size()];

        for (int i = 0; i != bodyIds.size(); i++)
        {
            rv[i] = BodyPartID.getInstance(bodyIds.getObjectAt(i));
        }

        return rv;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(pkiDataBodyid);
        v.add(bodyIds);

        return new DERSequence(v);
    }
}