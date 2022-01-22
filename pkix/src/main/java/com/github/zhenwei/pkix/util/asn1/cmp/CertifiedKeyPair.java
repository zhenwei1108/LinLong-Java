package com.github.zhenwei.pkix.util.asn1.cmp;


import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.ASN1TaggedObject;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.asn1.DERTaggedObject;
import crmf.EncryptedKey;
import crmf.EncryptedValue;
import crmf.PKIPublicationInfo;

/**
 * <pre>
 * CertifiedKeyPair ::= SEQUENCE {
 *                                  certOrEncCert       CertOrEncCert,
 *                                  privateKey      [0] EncryptedKey      OPTIONAL,
 *                                  -- see [CRMF] for comment on encoding
 *                                  publicationInfo [1] PKIPublicationInfo  OPTIONAL
 *       }
 * </pre>
 */
public class CertifiedKeyPair
    extends ASN1Object
{
    private CertOrEncCert certOrEncCert;
    private EncryptedKey privateKey;
    private PKIPublicationInfo  publicationInfo;

    private CertifiedKeyPair(ASN1Sequence seq)
    {
        certOrEncCert = CertOrEncCert.getInstance(seq.getObjectAt(0));

        if (seq.size() >= 2)
        {
            if (seq.size() == 2)
            {
                ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(seq.getObjectAt(1));
                if (tagged.getTagNo() == 0)
                {
                    privateKey = EncryptedKey.getInstance(tagged.getObject());
                }
                else
                {
                    publicationInfo = PKIPublicationInfo.getInstance(tagged.getObject());
                }
            }
            else
            {
                privateKey = EncryptedKey.getInstance(ASN1TaggedObject.getInstance(seq.getObjectAt(1)).getObject());
                publicationInfo = PKIPublicationInfo.getInstance(ASN1TaggedObject.getInstance(seq.getObjectAt(2)).getObject());
            }
        }
    }

    public static cmp.CertifiedKeyPair getInstance(Object o)
    {
        if (o instanceof cmp.CertifiedKeyPair)
        {
            return (cmp.CertifiedKeyPair)o;
        }

        if (o != null)
        {
            return new cmp.CertifiedKeyPair(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public CertifiedKeyPair(
        CertOrEncCert certOrEncCert)
    {
        this(certOrEncCert, (EncryptedKey)null, null);
    }

    public CertifiedKeyPair(
        CertOrEncCert certOrEncCert,
        EncryptedKey privateKey,
        PKIPublicationInfo  publicationInfo)
    {
        if (certOrEncCert == null)
        {
            throw new IllegalArgumentException("'certOrEncCert' cannot be null");
        }

        this.certOrEncCert = certOrEncCert;
        this.privateKey = privateKey;
        this.publicationInfo = publicationInfo;
    }

    public CertifiedKeyPair(
        CertOrEncCert certOrEncCert,
        EncryptedValue privateKey,
        PKIPublicationInfo  publicationInfo)
    {
        if (certOrEncCert == null)
        {
            throw new IllegalArgumentException("'certOrEncCert' cannot be null");
        }

        this.certOrEncCert = certOrEncCert;
        this.privateKey = (privateKey != null) ? new EncryptedKey(privateKey) : (EncryptedKey)null;
        this.publicationInfo = publicationInfo;
    }

    public CertOrEncCert getCertOrEncCert()
    {
        return certOrEncCert;
    }

    public EncryptedKey getPrivateKey()
    {
        return privateKey;
    }

    public PKIPublicationInfo getPublicationInfo()
    {
        return publicationInfo;
    }

    /**
     * Return the primitive representation of PKIPublicationInfo.
     *
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        v.add(certOrEncCert);

        if (privateKey != null)
        {
            v.add(new DERTaggedObject(true, 0, privateKey));
        }

        if (publicationInfo != null)
        {
            v.add(new DERTaggedObject(true, 1, publicationInfo));
        }

        return new DERSequence(v);
    }
}