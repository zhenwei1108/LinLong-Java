package com.github.zhenwei.pkix.util.asn1.cmc;


import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.ASN1Set;
import com.github.zhenwei.core.asn1.DERSequence;

/**
 * TaggedAttribute from RFC5272
 * <pre>
 * TaggedAttribute ::= SEQUENCE {
 * bodyPartID         BodyPartID,
 * attrType           OBJECT IDENTIFIER,
 * attrValues         SET OF AttributeValue
 * }
 * </pre>
 */
public class TaggedAttribute
    extends ASN1Object
{
    private final BodyPartID bodyPartID;
    private final ASN1ObjectIdentifier attrType;
    private final ASN1Set attrValues;

    public static cmc.TaggedAttribute getInstance(Object o)
    {
        if (o instanceof cmc.TaggedAttribute)
        {
            return (cmc.TaggedAttribute)o;
        }

        if (o != null)
        {
            return new cmc.TaggedAttribute(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    private TaggedAttribute(ASN1Sequence seq)
    {
        if (seq.size() != 3)
        {
            throw new IllegalArgumentException("incorrect sequence size");
        }
        this.bodyPartID = BodyPartID.getInstance(seq.getObjectAt(0));
        this.attrType = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(1));
        this.attrValues = ASN1Set.getInstance(seq.getObjectAt(2));
    }

    public TaggedAttribute(BodyPartID bodyPartID, ASN1ObjectIdentifier attrType, ASN1Set attrValues)
    {
        this.bodyPartID = bodyPartID;
        this.attrType = attrType;
        this.attrValues = attrValues;
    }

    public BodyPartID getBodyPartID()
    {
        return bodyPartID;
    }

    public ASN1ObjectIdentifier getAttrType()
    {
        return attrType;
    }

    public ASN1Set getAttrValues()
    {
        return attrValues;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(new ASN1Encodable[]{bodyPartID, attrType, attrValues});
    }
}