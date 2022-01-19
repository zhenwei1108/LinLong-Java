package com.github.zhenwei.sdk.util.asn1.tsp;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.Arrays;

public class MessageImprint
    extends ASN1Object
{
    AlgorithmIdentifier hashAlgorithm;
    byte[]              hashedMessage;
    
    /**
     * Return an instance of MessageImprint, or null, based on o.
     * 
     * @param o the object to be converted.
     * @return a MessageImprint object.
     */
    public static org.bouncycastle.asn1.tsp.MessageImprint getInstance(Object o)
    {
        if (o instanceof org.bouncycastle.asn1.tsp.MessageImprint)
        {
            return (org.bouncycastle.asn1.tsp.MessageImprint)o;
        }

        if (o != null)
        {
            return new org.bouncycastle.asn1.tsp.MessageImprint(ASN1Sequence.getInstance(o));
        }

        return null;
    }
    
    private MessageImprint(
        ASN1Sequence seq)
    {
        if (seq.size() == 2)
        {
            this.hashAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
            this.hashedMessage = ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets();
        }
        else
        {
            throw new IllegalArgumentException("sequence has wrong number of elements");
        }
    }
    
    public MessageImprint(
        AlgorithmIdentifier hashAlgorithm,
        byte[]              hashedMessage)
    {
        this.hashAlgorithm = hashAlgorithm;
        this.hashedMessage = Arrays.clone(hashedMessage);
    }
    
    public AlgorithmIdentifier getHashAlgorithm()
    {
        return hashAlgorithm;
    }
    
    public byte[] getHashedMessage()
    {
        return Arrays.clone(hashedMessage);
    }
    
    /**
     * <pre>
     *    MessageImprint ::= SEQUENCE  {
     *       hashAlgorithm                AlgorithmIdentifier,
     *       hashedMessage                OCTET STRING  }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(hashAlgorithm);
        v.add(new DEROctetString(hashedMessage));

        return new DERSequence(v);
    }
}