package com.github.zhenwei.pkix.cms;

import java.io.IOException;
import java.util.List;
import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.pkix.util.asn1.cmsIssuerAndSerialNumber;
import com.github.zhenwei.pkix.util.asn1.cmsKeyAgreeRecipientIdentifier;
import com.github.zhenwei.pkix.util.asn1.cmsKeyAgreeRecipientInfo;
import com.github.zhenwei.pkix.util.asn1.cmsOriginatorIdentifierOrKey;
import com.github.zhenwei.pkix.util.asn1.cmsOriginatorPublicKey;
import com.github.zhenwei.pkix.util.asn1.cmsRecipientEncryptedKey;
import com.github.zhenwei.pkix.util.asn1.cmsRecipientKeyIdentifier;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.asn1.x509.SubjectKeyIdentifier;
import com.github.zhenwei.core.asn1.x509.SubjectPublicKeyInfo;
import com.github.zhenwei.core.util.Arrays;

/**
 * the RecipientInfo class for a recipient who has been sent a message
 * encrypted using key agreement.
 */
public class KeyAgreeRecipientInformation
    extends RecipientInformation
{
    private KeyAgreeRecipientInfo info;
    private ASN1OctetString       encryptedKey;

    static void readRecipientInfo(List infos, KeyAgreeRecipientInfo info,
        AlgorithmIdentifier messageAlgorithm, CMSSecureReadable secureReadable, AuthAttributesProvider additionalData)
    {
        ASN1Sequence s = info.getRecipientEncryptedKeys();

        for (int i = 0; i < s.size(); ++i)
        {
            RecipientEncryptedKey id = RecipientEncryptedKey.getInstance(
                s.getObjectAt(i));

            RecipientId rid;

            KeyAgreeRecipientIdentifier karid = id.getIdentifier();
            IssuerAndSerialNumber iAndSN = karid.getIssuerAndSerialNumber();

            if (iAndSN != null)
            {
                rid = new KeyAgreeRecipientId(iAndSN.getName(), iAndSN.getSerialNumber().getValue());
            }
            else
            {
                RecipientKeyIdentifier rKeyID = karid.getRKeyID();

                // Note: 'date' and 'other' fields of RecipientKeyIdentifier appear to be only informational

                rid = new KeyAgreeRecipientId(rKeyID.getSubjectKeyIdentifier().getOctets());
            }

            infos.add(new KeyAgreeRecipientInformation(info, rid, id.getEncryptedKey(), messageAlgorithm,
                secureReadable, additionalData));
        }
    }

    KeyAgreeRecipientInformation(
        KeyAgreeRecipientInfo   info,
        RecipientId             rid,
        ASN1OctetString         encryptedKey,
        AlgorithmIdentifier     messageAlgorithm,
        CMSSecureReadable       secureReadable,
        AuthAttributesProvider  additionalData)
    {
        super(info.getKeyEncryptionAlgorithm(), messageAlgorithm, secureReadable, additionalData);

        this.info = info;
        this.rid = rid;
        this.encryptedKey = encryptedKey;
    }

    /**
     * Return the originator details for this recipient.
     *
     * @return the originator details.
     */
    public OriginatorIdentifierOrKey getOriginator()
    {
        return this.info.getOriginator();
    }

    /**
     * Return the userKeyingMaterial for this agreement recipient.
     *
     * @return the user keying material, null if absent.
     */
    public byte[] getUserKeyingMaterial()
    {
        ASN1OctetString ukm = this.info.getUserKeyingMaterial();
        if (ukm != null)
        {
            return Arrays.clone(ukm.getOctets());
        }

        return null;
    }

    private SubjectPublicKeyInfo getSenderPublicKeyInfo(AlgorithmIdentifier recKeyAlgId,
        OriginatorIdentifierOrKey originator)
        throws CMSException, IOException
    {
        OriginatorPublicKey opk = originator.getOriginatorKey();
        if (opk != null)
        {
            return getPublicKeyInfoFromOriginatorPublicKey(recKeyAlgId, opk);
        }

        OriginatorId origID;

        IssuerAndSerialNumber iAndSN = originator.getIssuerAndSerialNumber();
        if (iAndSN != null)
        {
            origID = new OriginatorId(iAndSN.getName(), iAndSN.getSerialNumber().getValue());
        }
        else
        {
            SubjectKeyIdentifier ski = originator.getSubjectKeyIdentifier();

            origID = new OriginatorId(ski.getKeyIdentifier());
        }

        return getPublicKeyInfoFromOriginatorId(origID);
    }

    private SubjectPublicKeyInfo getPublicKeyInfoFromOriginatorPublicKey(AlgorithmIdentifier recKeyAlgId,
            OriginatorPublicKey originatorPublicKey)
    {
        SubjectPublicKeyInfo pubInfo = new SubjectPublicKeyInfo(
            recKeyAlgId,
            originatorPublicKey.getPublicKey().getBytes());

        return pubInfo;
    }

    private SubjectPublicKeyInfo getPublicKeyInfoFromOriginatorId(OriginatorId origID)
            throws CMSException
    {
        // TODO Support all alternatives for OriginatorIdentifierOrKey
        // see RFC 3852 6.2.2
        throw new CMSException("No support for 'originator' as IssuerAndSerialNumber or SubjectKeyIdentifier");
    }

    protected RecipientOperator getRecipientOperator(Recipient recipient)
        throws CMSException, IOException
    {
        KeyAgreeRecipient agreeRecipient = (KeyAgreeRecipient)recipient;
        AlgorithmIdentifier    recKeyAlgId = agreeRecipient.getPrivateKeyAlgorithmIdentifier();

        return ((KeyAgreeRecipient)recipient).getRecipientOperator(keyEncAlg, messageAlgorithm, getSenderPublicKeyInfo(recKeyAlgId,
                        info.getOriginator()), info.getUserKeyingMaterial(), encryptedKey.getOctets());
    }
}