package com.github.zhenwei.pkix.cert.path.validations;

import X500Name;
import com.github.zhenwei.core.util.Memoable;
import com.github.zhenwei.core.util.Store;
import com.github.zhenwei.pkix.cert.X509CRLHolder;
import com.github.zhenwei.pkix.cert.X509CertificateHolder;
import com.github.zhenwei.pkix.cert.path.CertPathValidation;
import com.github.zhenwei.pkix.cert.path.CertPathValidationContext;
import com.github.zhenwei.pkix.cert.path.CertPathValidationException;
import java.util.Collection;
import java.util.Iterator;

 
 
 
 




public class CRLValidation
    implements CertPathValidation
{
    private Store crls;
    private X500Name workingIssuerName;

    public CRLValidation(X500Name trustAnchorName, Store crls)
    {
        this.workingIssuerName = trustAnchorName;
        this.crls = crls;
    }

    public void validate(CertPathValidationContext context, X509CertificateHolder certificate)
        throws CertPathValidationException
    {
        // TODO: add handling of delta CRLs
        Collection matches = crls.getMatches(new Selector()
        {
            public boolean match(Object obj)
            {
                X509CRLHolder crl = (X509CRLHolder)obj;

                return (crl.getIssuer().equals(workingIssuerName));
            }

            public Object clone()
            {
                return this;
            }
        });

        if (matches.isEmpty())
        {
            throw new CertPathValidationException("CRL for " + workingIssuerName + " not found");
        }

        for (Iterator it = matches.iterator(); it.hasNext();)
        {
            X509CRLHolder crl = (X509CRLHolder)it.next();

            // TODO: not quite right!
            if (crl.getRevokedCertificate(certificate.getSerialNumber()) != null)
            {
                throw new CertPathValidationException("Certificate revoked");
            }
        }

        this.workingIssuerName = certificate.getSubject();
    }

    public Memoable copy()
    {
        return new org.bouncycastle.cert.path.validations.CRLValidation(workingIssuerName, crls);
    }

    public void reset(Memoable other)
    {
        org.bouncycastle.cert.path.validations.CRLValidation v = (org.bouncycastle.cert.path.validations.CRLValidation)other;

        this.workingIssuerName = v.workingIssuerName;
        this.crls = v.crls;
    }
}