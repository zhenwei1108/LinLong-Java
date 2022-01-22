package com.github.zhenwei.core.asn1.pkcs;


import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.DERSequence;
import java.util.Enumeration;

public class PBES2Parameters
    extends ASN1Object
    implements PKCSObjectIdentifiers
{
    private KeyDerivationFunc func;
    private EncryptionScheme scheme;

    public static pkcs.PBES2Parameters getInstance(
        Object  obj)
    {
        if (obj instanceof pkcs.PBES2Parameters)
        {
            return (pkcs.PBES2Parameters)obj;
        }
        if (obj != null)
        {
            return new pkcs.PBES2Parameters(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public PBES2Parameters(KeyDerivationFunc keyDevFunc, EncryptionScheme encScheme)
    {
        this.func = keyDevFunc;
        this.scheme = encScheme;
    }

    private PBES2Parameters(
        ASN1Sequence  obj)
    {
        Enumeration e = obj.getObjects();
        ASN1Sequence  funcSeq = ASN1Sequence.getInstance(((ASN1Encodable)e.nextElement()).toASN1Primitive());

        if (funcSeq.getObjectAt(0).equals(id_PBKDF2))
        {
            func = new KeyDerivationFunc(id_PBKDF2, PBKDF2Params.getInstance(funcSeq.getObjectAt(1)));
        }
        else
        {
            func = KeyDerivationFunc.getInstance(funcSeq);
        }

        scheme = EncryptionScheme.getInstance(e.nextElement());
    }

    public KeyDerivationFunc getKeyDerivationFunc()
    {
        return func;
    }

    public EncryptionScheme getEncryptionScheme()
    {
        return scheme;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(func);
        v.add(scheme);

        return new DERSequence(v);
    }
}