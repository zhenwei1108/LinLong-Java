package com.github.zhenwei.core.asn1.pkcs;









import java.util.Enumeration;

public class EncryptedPrivateKeyInfo
    extends ASN1Object
{
    private AlgorithmIdentifier algId;
    private ASN1OctetString     data;

    private EncryptedPrivateKeyInfo(
        ASN1Sequence  seq)
    {
        Enumeration e = seq.getObjects();

        algId = AlgorithmIdentifier.getInstance(e.nextElement());
        data = ASN1OctetString.getInstance(e.nextElement());
    }

    public EncryptedPrivateKeyInfo(
        AlgorithmIdentifier algId,
        byte[]              encoding)
    {
        this.algId = algId;
        this.data = new DEROctetString(encoding);
    }

    public static pkcs.EncryptedPrivateKeyInfo getInstance(
        Object  obj)
    {
        if (obj instanceof pkcs.EncryptedPrivateKeyInfo)
        {
            return (pkcs.EncryptedPrivateKeyInfo)obj;
        }
        else if (obj != null)
        { 
            return new pkcs.EncryptedPrivateKeyInfo(ASN1Sequence.getInstance(obj));
        }

        return null;
    }
    
    public AlgorithmIdentifier getEncryptionAlgorithm()
    {
        return algId;
    }

    public byte[] getEncryptedData()
    {
        return data.getOctets();
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * EncryptedPrivateKeyInfo ::= SEQUENCE {
     *      encryptionAlgorithm AlgorithmIdentifier {{KeyEncryptionAlgorithms}},
     *      encryptedData EncryptedData
     * }
     *
     * EncryptedData ::= OCTET STRING
     *
     * KeyEncryptionAlgorithms ALGORITHM-IDENTIFIER ::= {
     *          ... -- For local profiles
     * }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(algId);
        v.add(data);

        return new DERSequence(v);
    }
}