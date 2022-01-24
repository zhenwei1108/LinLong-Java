package com.github.zhenwei.core.asn1.bc;

import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.DEROctetString;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.util.Arrays;

/**
 * <pre>
 *     EncryptedSecretKeyData ::= SEQUENCE {
 *         keyEncryptionAlgorithm AlgorithmIdentifier,
 *         encryptedKeyData OCTET STRING
 *     }
 * </pre>
 */
public class EncryptedSecretKeyData
    extends ASN1Object
{
    private final AlgorithmIdentifier keyEncryptionAlgorithm;
    private final ASN1OctetString encryptedKeyData;

    public EncryptedSecretKeyData(AlgorithmIdentifier keyEncryptionAlgorithm, byte[] encryptedKeyData)
    {
        this.keyEncryptionAlgorithm = keyEncryptionAlgorithm;
        this.encryptedKeyData = new DEROctetString(Arrays.clone(encryptedKeyData));
    }

    private EncryptedSecretKeyData(ASN1Sequence seq)
    {
        this.keyEncryptionAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        this.encryptedKeyData = ASN1OctetString.getInstance(seq.getObjectAt(1));
    }

    public static EncryptedSecretKeyData getInstance(Object o)
    {
        if (o instanceof EncryptedSecretKeyData)
        {
            return (EncryptedSecretKeyData)o;
        }
        else if (o != null)
        {
            return new EncryptedSecretKeyData(ASN1Sequence.getInstance(o));
        }

        return null;
    }


    public AlgorithmIdentifier getKeyEncryptionAlgorithm()
    {
        return keyEncryptionAlgorithm;
    }

    public byte[] getEncryptedKeyData()
    {
        return Arrays.clone(encryptedKeyData.getOctets());
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(keyEncryptionAlgorithm);
        v.add(encryptedKeyData);

        return new DERSequence(v);
    }
}