package com.github.zhenwei.core.asn1.mozilla;

import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

/**
 * This is designed to parse
 * the PublicKeyAndChallenge created by the KEYGEN tag included by
 * Mozilla based browsers.
 *  <pre>
 *  PublicKeyAndChallenge ::= SEQUENCE {
 *    spki SubjectPublicKeyInfo,
 *    challenge IA5STRING
 *  }
 *
 *  </pre>
 */
public class PublicKeyAndChallenge
    extends ASN1Object
{
    private ASN1Sequence         pkacSeq;
    private SubjectPublicKeyInfo spki;
    private ASN1IA5String         challenge;

    public static org.bouncycastle.asn1.mozilla.PublicKeyAndChallenge getInstance(Object obj)
    {
        if (obj instanceof org.bouncycastle.asn1.mozilla.PublicKeyAndChallenge)
        {
            return (org.bouncycastle.asn1.mozilla.PublicKeyAndChallenge)obj;
        }
        else if (obj != null)
        {
            return new org.bouncycastle.asn1.mozilla.PublicKeyAndChallenge(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private PublicKeyAndChallenge(ASN1Sequence seq)
    {
        pkacSeq = seq;
        spki = SubjectPublicKeyInfo.getInstance(seq.getObjectAt(0));
        challenge = ASN1IA5String.getInstance(seq.getObjectAt(1));
    }

    public ASN1Primitive toASN1Primitive()
    {
        return pkacSeq;
    }

    public SubjectPublicKeyInfo getSubjectPublicKeyInfo()
    {
        return spki;
    }

    /**
     * @deprecated Use {@link #getChallengeIA5()} instead.
     */
    public DERIA5String getChallenge()
    {
        return null == challenge || challenge instanceof DERIA5String
            ?   (DERIA5String)challenge
            :   new DERIA5String(challenge.getString(), false);
    }

    public ASN1IA5String getChallengeIA5()
    {
        return challenge;
    }
}