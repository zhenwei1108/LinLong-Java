package com.github.zhenwei.provider.jcajce.interfaces;

import TBSCertificate;
import X500Name;

/**
 * Interface exposing some additional methods on a BC native certificate object.
 */
public interface BCX509Certificate
{
    /**
     * Return the certificate issuer as an X500Name.
     *
     * @return the issuer.
     */
    X500Name getIssuerX500Name();

    /**
     * Return the ASN.1 class representing the TBSCertificate for this certificate.
     *
     * @return the issuer.
     */
    TBSCertificate getTBSCertificateNative();

    /**
     * Return the certificate subject as an X500Name.
     *
     * @return the issuer.
     */
    X500Name getSubjectX500Name();
}