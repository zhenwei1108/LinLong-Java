package com.github.zhenwei.pkix.cert;


import AttCertIssuer;
import GeneralNames;
import V2Form;
import X500Name;
import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.x509.GeneralName;
import java.util.ArrayList;
import java.util.List;


/**
 * Carrying class for an attribute certificate issuer.
 */
public class AttributeCertificateIssuer
    implements Selector
{
    final ASN1Encodable form;

    /**
     * Set the issuer directly with the ASN.1 structure.
     *
     * @param issuer The issuer
     */
    public AttributeCertificateIssuer(AttCertIssuer issuer)
    {
        form = issuer.getIssuer();
    }

    public AttributeCertificateIssuer(X500Name principal)
    {
        form = new V2Form(new GeneralNames(new GeneralName(principal)));
    }

    public X500Name[] getNames()
    {
        GeneralNames name;

        if (form instanceof V2Form)
        {
            name = ((V2Form)form).getIssuerName();
        }
        else
        {
            name = (GeneralNames)form;
        }

        GeneralName[] names = name.getNames();

        List l = new ArrayList(names.length);

        for (int i = 0; i != names.length; i++)
        {
            if (names[i].getTagNo() == GeneralName.directoryName)
            {
                l.add(X500Name.getInstance(names[i].getName()));
            }
        }

        return (X500Name[])l.toArray(new X500Name[l.size()]);
    }

    private boolean matchesDN(X500Name subject, GeneralNames targets)
    {
        GeneralName[] names = targets.getNames();

        for (int i = 0; i != names.length; i++)
        {
            GeneralName gn = names[i];

            if (gn.getTagNo() == GeneralName.directoryName)
            {
                if (X500Name.getInstance(gn.getName()).equals(subject))
                {
                    return true;
                }
            }
        }

        return false;
    }

    public Object clone()
    {
        return new org.bouncycastle.cert.AttributeCertificateIssuer(AttCertIssuer.getInstance(form));
    }

    public boolean equals(Object obj)
    {
        if (obj == this)
        {
            return true;
        }

        if (!(obj instanceof org.bouncycastle.cert.AttributeCertificateIssuer))
        {
            return false;
        }

        org.bouncycastle.cert.AttributeCertificateIssuer other = (org.bouncycastle.cert.AttributeCertificateIssuer)obj;

        return this.form.equals(other.form);
    }

    public int hashCode()
    {
        return this.form.hashCode();
    }

    public boolean match(Object obj)
    {
        if (!(obj instanceof X509CertificateHolder))
        {
            return false;
        }

        X509CertificateHolder x509Cert = (X509CertificateHolder)obj;

        if (form instanceof V2Form)
        {
            V2Form issuer = (V2Form)form;
            if (issuer.getBaseCertificateID() != null)
            {
                return issuer.getBaseCertificateID().getSerial().hasValue(x509Cert.getSerialNumber())
                    && matchesDN(x509Cert.getIssuer(), issuer.getBaseCertificateID().getIssuer());
            }

            GeneralNames name = issuer.getIssuerName();
            if (matchesDN(x509Cert.getSubject(), name))
            {
                return true;
            }
        }
        else
        {
            GeneralNames name = (GeneralNames)form;
            if (matchesDN(x509Cert.getSubject(), name))
            {
                return true;
            }
        }

        return false;
    }
}