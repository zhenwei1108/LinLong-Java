package com.github.zhenwei.core.asn1.x9;







import DERBitString;


/**
 * @deprecated use ValidationParams
 */
public class DHValidationParms extends ASN1Object
{
    private DERBitString seed;
    private ASN1Integer pgenCounter;

    public static x9.DHValidationParms getInstance(ASN1TaggedObject obj, boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static x9.DHValidationParms getInstance(Object obj)
    {
        if (obj instanceof x9.DHValidationParms)
        {
            return (x9.DHValidationParms)obj;
        }
        else if (obj != null)
        {
            return new x9.DHValidationParms(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public DHValidationParms(DERBitString seed, ASN1Integer pgenCounter)
    {
        if (seed == null)
        {
            throw new IllegalArgumentException("'seed' cannot be null");
        }
        if (pgenCounter == null)
        {
            throw new IllegalArgumentException("'pgenCounter' cannot be null");
        }

        this.seed = seed;
        this.pgenCounter = pgenCounter;
    }

    private DHValidationParms(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }

        this.seed = DERBitString.getInstance(seq.getObjectAt(0));
        this.pgenCounter = ASN1Integer.getInstance(seq.getObjectAt(1));
    }

    public DERBitString getSeed()
    {
        return this.seed;
    }

    public ASN1Integer getPgenCounter()
    {
        return this.pgenCounter;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.seed);
        v.add(this.pgenCounter);
        return new DERSequence(v);
    }
}