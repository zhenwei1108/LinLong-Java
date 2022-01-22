package com.github.zhenwei.pkix.cms;

import X500Name;
import java.math.BigInteger;
import org.bouncycastle.cert.selector.X509CertificateHolderSelector;

public class KeyAgreeRecipientId
    extends RecipientId
{
    private X509CertificateHolderSelector baseSelector;

    private KeyAgreeRecipientId(X509CertificateHolderSelector baseSelector)
    {
        super(keyAgree);

        this.baseSelector = baseSelector;
    }

    /**
     * Construct a key agree recipient ID with the value of a public key's subjectKeyId.
     *
     * @param subjectKeyId a subjectKeyId
     */
    public KeyAgreeRecipientId(byte[] subjectKeyId)
    {
        this(null, null, subjectKeyId);
    }

    /**
     * Construct a key agree recipient ID based on the issuer and serial number of the recipient's associated
     * certificate.
     *
     * @param issuer the issuer of the recipient's associated certificate.
     * @param serialNumber the serial number of the recipient's associated certificate.
     */
    public KeyAgreeRecipientId(X500Name issuer, BigInteger serialNumber)
    {
        this(issuer, serialNumber, null);
    }

    public KeyAgreeRecipientId(X500Name issuer, BigInteger serialNumber, byte[] subjectKeyId)
    {
        this(new X509CertificateHolderSelector(issuer, serialNumber, subjectKeyId));
    }

    public X500Name getIssuer()
    {
        return baseSelector.getIssuer();
    }

    public BigInteger getSerialNumber()
    {
        return baseSelector.getSerialNumber();
    }

    public byte[] getSubjectKeyIdentifier()
    {
        return baseSelector.getSubjectKeyIdentifier();
    }

    public int hashCode()
    {
        return baseSelector.hashCode();
    }

    public boolean equals(
        Object  o)
    {
        if (!(o instanceof org.bouncycastle.cms.KeyAgreeRecipientId))
        {
            return false;
        }

        org.bouncycastle.cms.KeyAgreeRecipientId id = (org.bouncycastle.cms.KeyAgreeRecipientId)o;

        return this.baseSelector.equals(id.baseSelector);
    }

    public Object clone()
    {
        return new org.bouncycastle.cms.KeyAgreeRecipientId(baseSelector);
    }

    public boolean match(Object obj)
    {
        if (obj instanceof KeyAgreeRecipientInformation)
        {
            return ((KeyAgreeRecipientInformation)obj).getRID().equals(this);
        }

        return baseSelector.match(obj);
    }
}