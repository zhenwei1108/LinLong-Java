package com.github.zhenwei.sdk.util.asn1.cmc;







/**
 * <pre>
 *    BodyPartPath ::= SEQUENCE SIZE (1..MAX) OF BodyPartID
 * </pre>
 */
public class BodyPartPath
    extends ASN1Object
{
    private final BodyPartID[] bodyPartIDs;

    public static cmc.BodyPartPath getInstance(
        Object  obj)
    {
        if (obj instanceof cmc.BodyPartPath)
        {
            return (cmc.BodyPartPath)obj;
        }

        if (obj != null)
        {
            return new cmc.BodyPartPath(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static cmc.BodyPartPath getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    /**
     * Construct a BodyPartPath object containing one BodyPartID.
     *
     * @param bodyPartID the BodyPartID to be contained.
     */
    public BodyPartPath(
        BodyPartID  bodyPartID)
    {
        this.bodyPartIDs = new BodyPartID[] { bodyPartID };
    }


    public BodyPartPath(
        BodyPartID[] bodyPartIDs)
    {
        this.bodyPartIDs = Utils.clone(bodyPartIDs);
    }

    private BodyPartPath(
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