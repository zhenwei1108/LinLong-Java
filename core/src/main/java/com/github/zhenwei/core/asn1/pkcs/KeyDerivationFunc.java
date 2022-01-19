package com.github.zhenwei.core.asn1.pkcs;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

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

    public static org.bouncycastle.asn1.pkcs.KeyDerivationFunc getInstance(Object obj)
    {
        if (obj instanceof org.bouncycastle.asn1.pkcs.KeyDerivationFunc)
        {
            return (org.bouncycastle.asn1.pkcs.KeyDerivationFunc)obj;
        }
        else if (obj != null)
        {
            return new org.bouncycastle.asn1.pkcs.KeyDerivationFunc(ASN1Sequence.getInstance(obj));
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