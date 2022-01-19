package com.github.zhenwei.sdk.util.asn1.esf;

import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.esf.CrlOcspRef;

/**
 * <pre>
 * CompleteRevocationRefs ::= SEQUENCE OF CrlOcspRef
 * </pre>
 */
public class CompleteRevocationRefs
    extends ASN1Object
{

    private ASN1Sequence crlOcspRefs;

    public static org.bouncycastle.asn1.esf.CompleteRevocationRefs getInstance(Object obj)
    {
        if (obj instanceof org.bouncycastle.asn1.esf.CompleteRevocationRefs)
        {
            return (org.bouncycastle.asn1.esf.CompleteRevocationRefs)obj;
        }
        else if (obj != null)
        {
            return new org.bouncycastle.asn1.esf.CompleteRevocationRefs(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private CompleteRevocationRefs(ASN1Sequence seq)
    {
        Enumeration seqEnum = seq.getObjects();
        while (seqEnum.hasMoreElements())
        {
            CrlOcspRef.getInstance(seqEnum.nextElement());
        }
        this.crlOcspRefs = seq;
    }

    public CompleteRevocationRefs(CrlOcspRef[] crlOcspRefs)
    {
        this.crlOcspRefs = new DERSequence(crlOcspRefs);
    }

    public CrlOcspRef[] getCrlOcspRefs()
    {
        CrlOcspRef[] result = new CrlOcspRef[this.crlOcspRefs.size()];
        for (int idx = 0; idx < result.length; idx++)
        {
            result[idx] = CrlOcspRef.getInstance(this.crlOcspRefs
                .getObjectAt(idx));
        }
        return result;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return this.crlOcspRefs;
    }
}