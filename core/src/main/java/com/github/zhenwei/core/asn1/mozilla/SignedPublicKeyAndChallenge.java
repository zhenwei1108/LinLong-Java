package com.github.zhenwei.core.asn1.mozilla;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.mozilla.PublicKeyAndChallenge;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * <pre>
 *  SignedPublicKeyAndChallenge ::= SEQUENCE {
 *    publicKeyAndChallenge PublicKeyAndChallenge,
 *    signatureAlgorithm AlgorithmIdentifier,
 *    signature BIT STRING
 *  }
 *
 *  </pre>
 */
public class SignedPublicKeyAndChallenge
    extends ASN1Object
{
    private final PublicKeyAndChallenge pubKeyAndChal;
    private final ASN1Sequence pkacSeq;

    public static org.bouncycastle.asn1.mozilla.SignedPublicKeyAndChallenge getInstance(Object obj)
    {
        if (obj instanceof org.bouncycastle.asn1.mozilla.SignedPublicKeyAndChallenge)
        {
            return (org.bouncycastle.asn1.mozilla.SignedPublicKeyAndChallenge)obj;
        }
        else if (obj != null)
        {
            return new org.bouncycastle.asn1.mozilla.SignedPublicKeyAndChallenge(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private SignedPublicKeyAndChallenge(ASN1Sequence seq)
    {
        pkacSeq = seq;
        pubKeyAndChal = PublicKeyAndChallenge.getInstance(seq.getObjectAt(0));
    }

    public ASN1Primitive toASN1Primitive()
    {
        return pkacSeq;
    }

    public PublicKeyAndChallenge getPublicKeyAndChallenge()
    {
        return pubKeyAndChal;
    }

    public AlgorithmIdentifier getSignatureAlgorithm()
    {
        return AlgorithmIdentifier.getInstance(pkacSeq.getObjectAt(1));
    }

    public DERBitString getSignature()
    {
        return DERBitString.getInstance(pkacSeq.getObjectAt(2));
    }
}