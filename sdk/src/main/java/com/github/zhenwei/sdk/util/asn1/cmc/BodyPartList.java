package com.github.zhenwei.sdk.util.asn1.cmc;







/**
 * <pre>
 *   BodyPartList ::= SEQUENCE SIZE (1..MAX) OF BodyPartID
 * </pre>
 */
public class BodyPartList
    extends ASN1Object
{
    private final BodyPartID[] bodyPartIDs;

    public static cmc.BodyPartList getInstance(
        Object  obj)
    {
        if (obj instanceof cmc.BodyPartList)
        {
            return (cmc.BodyPartList)obj;
        }

        if (obj != null)
        {
            return new cmc.BodyPartList(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static cmc.BodyPartList getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    /**
     * Construct a BodyPartList object containing one BodyPartID.
     *
     * @param bodyPartID the BodyPartID to be contained.
     */
    public BodyPartList(
        BodyPartID  bodyPartID)
    {
        this.bodyPartIDs = new BodyPartID[] { bodyPartID };
    }


    public BodyPartList(
        BodyPartID[] bodyPartIDs)
    {
        this.bodyPartIDs = Utils.clone(bodyPartIDs);
    }

    private BodyPartList(
        ASN1Sequence  seq)
    {
        this.bodyPartIDs = Utils.toBodyPartIDArray(seq);
    }

    public BodyPartID[] getBodyPartIDs()
    {
        return Utils.clone(bodyPartIDs);
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(bodyPartIDs);
    }
}