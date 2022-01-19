package com.github.zhenwei.sdk.util.asn1.eac;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.eac.ECDSAPublicKey;
import org.bouncycastle.asn1.eac.RSAPublicKey;

public abstract class PublicKeyDataObject
    extends ASN1Object
{
    public static org.bouncycastle.asn1.eac.PublicKeyDataObject getInstance(Object obj)
    {
        if (obj instanceof org.bouncycastle.asn1.eac.PublicKeyDataObject)
        {
            return (org.bouncycastle.asn1.eac.PublicKeyDataObject)obj;
        }
        if (obj != null)
        {
            ASN1Sequence seq = ASN1Sequence.getInstance(obj);
            ASN1ObjectIdentifier usage = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));

            if (usage.on(EACObjectIdentifiers.id_TA_ECDSA))
            {
                return new ECDSAPublicKey(seq);
            }
            else
            {
                return new RSAPublicKey(seq);
            }
        }

        return null;
    }

    public abstract ASN1ObjectIdentifier getUsage();
}