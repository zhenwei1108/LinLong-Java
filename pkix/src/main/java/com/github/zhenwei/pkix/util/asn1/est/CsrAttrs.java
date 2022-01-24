package com.github.zhenwei.pkix.util.asn1.est;

import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.ASN1TaggedObject;
import com.github.zhenwei.core.asn1.DERSequence;

/**
 * <pre>
 *      CsrAttrs ::= SEQUENCE SIZE (0..MAX) OF AttrOrOID
 * </pre>
 */
public class CsrAttrs
    extends ASN1Object
{
    private final AttrOrOID[] attrOrOIDs;

    public static CsrAttrs getInstance(
        Object obj)
    {
        if (obj instanceof CsrAttrs)
        {
            return (CsrAttrs)obj;
        }

        if (obj != null)
        {
            return new CsrAttrs(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static CsrAttrs getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    /**
     * Construct a CsrAttrs object containing one AttrOrOID.
     *
     * @param attrOrOID the AttrOrOID to be contained.
     */
    public CsrAttrs(
        AttrOrOID attrOrOID)
    {
        this.attrOrOIDs = new AttrOrOID[]{attrOrOID};
    }


    public CsrAttrs(
        AttrOrOID[] attrOrOIDs)
    {
        this.attrOrOIDs = Utils.clone(attrOrOIDs);
    }

    private CsrAttrs(
        ASN1Sequence seq)
    {
        this.attrOrOIDs = new AttrOrOID[seq.size()];

        for (int i = 0; i != seq.size(); i++)
        {
            attrOrOIDs[i] = AttrOrOID.getInstance(seq.getObjectAt(i));
        }
    }

    public AttrOrOID[] getAttrOrOIDs()
    {
        return Utils.clone(attrOrOIDs);
    }

    public int size()
    {
        return attrOrOIDs.length;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(attrOrOIDs);
    }
}