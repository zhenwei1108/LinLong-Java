package com.github.zhenwei.pkix.util.asn1.cms;

import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.DEROctetString;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.util.Arrays;

/**
 * <a href="https://tools.ietf.org/html/rfc5084">RFC 5084</a>: CCMParameters object.
 * <p>
 * <pre>
 CCMParameters ::= SEQUENCE {
   aes-nonce        OCTET STRING, -- recommended size is 12 octets
   aes-ICVlen       AES-CCM-ICVlen DEFAULT 12 }
 * </pre>
 */
public class CCMParameters
    extends ASN1Object
{
    private byte[] nonce;
    private int icvLen;

    /**
     * Return an CCMParameters object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link com.github.zhenwei.pkix.util.asn1.cms.CCMParameters} object
     * <li> {@link com.github.zhenwei.core.asn1.ASN1Sequence#getInstance(Object) ASN1Sequence} input formats with CCMParameters structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static CCMParameters getInstance(
        Object  obj)
    {
        if (obj instanceof CCMParameters)
        {
            return (CCMParameters)obj;
        }
        else if (obj != null)
        {
            return new CCMParameters(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private CCMParameters(
        ASN1Sequence seq)
    {
        this.nonce = ASN1OctetString.getInstance(seq.getObjectAt(0)).getOctets();

        if (seq.size() == 2)
        {
            this.icvLen = ASN1Integer.getInstance(seq.getObjectAt(1)).intValueExact();
        }
        else
        {
            this.icvLen = 12;
        }
    }

    public CCMParameters(
        byte[] nonce,
        int icvLen)
    {
        this.nonce = Arrays.clone(nonce);
        this.icvLen = icvLen;
    }

    public byte[] getNonce()
    {
        return Arrays.clone(nonce);
    }

    public int getIcvLen()
    {
        return icvLen;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(new DEROctetString(nonce));

        if (icvLen != 12)
        {
            v.add(new ASN1Integer(icvLen));
        }

        return new DERSequence(v);
    }
}