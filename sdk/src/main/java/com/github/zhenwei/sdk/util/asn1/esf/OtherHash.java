package com.github.zhenwei.sdk.util.asn1.esf;









/**
 * <pre>
 * OtherHash ::= CHOICE {
 *    sha1Hash  OtherHashValue, -- This contains a SHA-1 hash
 *   otherHash  OtherHashAlgAndValue
 *  }
 * </pre>
 */
public class OtherHash
    extends ASN1Object
    implements ASN1Choice
{

    private ASN1OctetString sha1Hash;
    private OtherHashAlgAndValue otherHash;

    public static esf.OtherHash getInstance(Object obj)
    {
        if (obj instanceof esf.OtherHash)
        {
            return (esf.OtherHash)obj;
        }
        if (obj instanceof ASN1OctetString)
        {
            return new esf.OtherHash((ASN1OctetString)obj);
        }
        return new esf.OtherHash(OtherHashAlgAndValue.getInstance(obj));
    }

    private OtherHash(ASN1OctetString sha1Hash)
    {
        this.sha1Hash = sha1Hash;
    }

    public OtherHash(OtherHashAlgAndValue otherHash)
    {
        this.otherHash = otherHash;
    }

    public OtherHash(byte[] sha1Hash)
    {
        this.sha1Hash = new DEROctetString(sha1Hash);
    }

    public AlgorithmIdentifier getHashAlgorithm()
    {
        if (null == this.otherHash)
        {
            return new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1);
        }
        return this.otherHash.getHashAlgorithm();
    }

    public byte[] getHashValue()
    {
        if (null == this.otherHash)
        {
            return this.sha1Hash.getOctets();
        }
        return this.otherHash.getHashValue().getOctets();
    }

    public ASN1Primitive toASN1Primitive()
    {
        if (null == this.otherHash)
        {
            return this.sha1Hash;
        }
        return this.otherHash.toASN1Primitive();
    }
}