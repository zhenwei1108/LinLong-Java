package com.github.zhenwei.pkix.cms;

import X500Name;
import java.math.BigInteger;
import org.bouncycastle.cert.selector.X509CertificateHolderSelector;


/**
 * a basic index for a signer.
 */
public class SignerId
    implements Selector
{
    private X509CertificateHolderSelector baseSelector;

    private SignerId(X509CertificateHolderSelector baseSelector)
    {
        this.baseSelector = baseSelector;
    }

    /**
     * Construct a signer ID with the value of a public key's subjectKeyId.
     *
     * @param subjectKeyId a subjectKeyId
     */
    public SignerId(byte[] subjectKeyId)
    {
        this(null, null, subjectKeyId);
    }

    /**
     * Construct a signer ID based on the issuer and serial number of the signer's associated
     * certificate.
     *
     * @param issuer the issuer of the signer's associated certificate.
     * @param serialNumber the serial number of the signer's associated certificate.
     */
    public SignerId(X500Name issuer, BigInteger serialNumber)
    {
        this(issuer, serialNumber, null);
    }

    /**
     * Construct a signer ID based on the issuer and serial number of the signer's associated
     * certificate.
     *
     * @param issuer the issuer of the signer's associated certificate.
     * @param serialNumber the serial number of the signer's associated certificate.
     * @param subjectKeyId the subject key identifier to use to match the signers associated certificate.
     */
    public SignerId(X500Name issuer, BigInteger serialNumber, byte[] subjectKeyId)
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
        if (!(o instanceof org.bouncycastle.cms.SignerId))
        {
            return false;
        }

        org.bouncycastle.cms.SignerId id = (org.bouncycastle.cms.SignerId)o;

        return this.baseSelector.equals(id.baseSelector);
    }

    public boolean match(Object obj)
    {
        if (obj instanceof SignerInformation)
        {
            return ((SignerInformation)obj).getSID().equals(this);
        }

        return baseSelector.match(obj);
    }

    public Object clone()
    {
        return new org.bouncycastle.cms.SignerId(this.baseSelector);
    }
}