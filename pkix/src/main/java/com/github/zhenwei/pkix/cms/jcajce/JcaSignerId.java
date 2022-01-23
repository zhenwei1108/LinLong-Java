package com.github.zhenwei.pkix.cms.jcajce;

import SignerId;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;

public class JcaSignerId
    extends SignerId
{
    /**
     * Construct a signer identifier based on the issuer, serial number and subject key identifier (if present) of the passed in
     * certificate.
     *
     * @param certificate certificate providing the issue and serial number and subject key identifier.
     */
    public JcaSignerId(X509Certificate certificate)
    {
        super(convertPrincipal(certificate.getIssuerX500Principal()), certificate.getSerialNumber(), CMSUtils.getSubjectKeyId(certificate));
    }

    /**
     * Construct a signer identifier based on the provided issuer and serial number..
     *
     * @param issuer the issuer to use.
     * @param serialNumber  the serial number to use.
     */
    public JcaSignerId(X500Principal issuer, BigInteger serialNumber)
    {
        super(convertPrincipal(issuer), serialNumber);
    }

    /**
     * Construct a signer identifier based on the provided issuer, serial number, and subjectKeyId..
     *
     * @param issuer the issuer to use.
     * @param serialNumber  the serial number to use.
     * @param subjectKeyId the subject key ID to use.
     */
    public JcaSignerId(X500Principal issuer, BigInteger serialNumber, byte[] subjectKeyId)
    {
        super(convertPrincipal(issuer), serialNumber, subjectKeyId);
    }

    private static X500Name convertPrincipal(X500Principal issuer)
    {
        if (issuer == null)
        {
            return null;
        }
        return X500Name.getInstance(issuer.getEncoded());
    }
}