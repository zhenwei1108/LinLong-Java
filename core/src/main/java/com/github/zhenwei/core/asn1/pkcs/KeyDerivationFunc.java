package com.github.zhenwei.core.asn1.pkcs;








public class KeyDerivationFunc
    extends ASN1Object
{
    private AlgorithmIdentifier algId;

    public KeyDerivationFunc(
        ASN1ObjectIdentifier objectId,
        ASN1Encodable parameters)
    {
        this.algId = new AlgorithmIdentifier(objectId, parameters);
    }

    private KeyDerivationFunc(
        ASN1Sequence seq)
    {
        this.algId = AlgorithmIdentifier.getInstance(seq);
    }

    public static pkcs.KeyDerivationFunc getInstance(Object obj)
    {
        if (obj instanceof pkcs.KeyDerivationFunc)
        {
            return (pkcs.KeyDerivationFunc)obj;
        }
        else if (obj != null)
        {
            return new pkcs.KeyDerivationFunc(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public ASN1ObjectIdentifier getAlgorithm()
    {
        return algId.getAlgorithm();
    }

    public ASN1Encodable getParameters()
    {
        return algId.getParameters();
    }

    public ASN1Primitive toASN1Primitive()
    {
        return algId.toASN1Primitive();
    }
}