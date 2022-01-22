package com.github.zhenwei.pkix.cert.path.validations;


import KeyUsage;
import com.github.zhenwei.core.asn1.x509.Extension;
import com.github.zhenwei.core.util.Memoable;
import com.github.zhenwei.pkix.cert.X509CertificateHolder;
import com.github.zhenwei.pkix.cert.path.CertPathValidation;
import com.github.zhenwei.pkix.cert.path.CertPathValidationContext;
import com.github.zhenwei.pkix.cert.path.CertPathValidationException;


public class KeyUsageValidation
    implements CertPathValidation
{
    private boolean          isMandatory;

    public KeyUsageValidation()
    {
        this(true);
    }

    public KeyUsageValidation(boolean isMandatory)
    {
        this.isMandatory = isMandatory;
    }

    public void validate(CertPathValidationContext context, X509CertificateHolder certificate)
        throws CertPathValidationException
    {
        context.addHandledExtension(Extension.keyUsage);

        if (!context.isEndEntity())
        {
            KeyUsage usage = KeyUsage.fromExtensions(certificate.getExtensions());

            if (usage != null)
            {
                if (!usage.hasUsages(KeyUsage.keyCertSign))
                {
                    throw new CertPathValidationException("Issuer certificate KeyUsage extension does not permit key signing");
                }
            }
            else
            {
                if (isMandatory)
                {
                    throw new CertPathValidationException("KeyUsage extension not present in CA certificate");
                }
            }
        }
    }

    public Memoable copy()
    {
        return new org.bouncycastle.cert.path.validations.KeyUsageValidation(isMandatory);
    }

    public void reset(Memoable other)
    {
        org.bouncycastle.cert.path.validations.KeyUsageValidation v = (org.bouncycastle.cert.path.validations.KeyUsageValidation)other;

        this.isMandatory = v.isMandatory;
    }
}