package com.github.zhenwei.sdk.util.asn1.cmc;







import cms.ContentInfo;

/**
 * <pre>
 * TaggedContentInfo ::= SEQUENCE {
 *       bodyPartID              BodyPartID,
 *       contentInfo             ContentInfo
 * }
 * </pre>
 */
public class TaggedContentInfo
    extends ASN1Object
{
    private final BodyPartID bodyPartID;
    private final ContentInfo contentInfo;

    public TaggedContentInfo(BodyPartID bodyPartID, ContentInfo contentInfo)
    {
        this.bodyPartID = bodyPartID;
        this.contentInfo = contentInfo;
    }

    private TaggedContentInfo(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("incorrect sequence size");
        }
        this.bodyPartID = BodyPartID.getInstance(seq.getObjectAt(0));
        this.contentInfo = ContentInfo.getInstance(seq.getObjectAt(1));
    }

    public static cmc.TaggedContentInfo getInstance(Object o)
    {
        if (o instanceof cmc.TaggedContentInfo)
        {
            return (cmc.TaggedContentInfo)o;
        }

        if (o != null)
        {
            return new cmc.TaggedContentInfo(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public static cmc.TaggedContentInfo getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(bodyPartID);
        v.add(contentInfo);

        return new DERSequence(v);
    }

    public BodyPartID getBodyPartID()
    {
        return bodyPartID;
    }

    public ContentInfo getContentInfo()
    {
        return contentInfo;
    }
}