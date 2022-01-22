package com.github.zhenwei.pkix.pkcs;




import Certificate;
import CertificateList;


import java.io.IOException;
import org.bouncycastle.cert.X509CRLHolder;
 
import org.bouncycastle.operator.OutputEncryptor;
import pkcs.Attribute;


import pkcs.PrivateKeyInfo;


public class PKCS12SafeBagBuilder
{
    private ASN1ObjectIdentifier bagType;
    private ASN1Encodable        bagValue;
    private ASN1EncodableVector  bagAttrs = new ASN1EncodableVector();

    public PKCS12SafeBagBuilder(PrivateKeyInfo privateKeyInfo, OutputEncryptor encryptor)
    {
        this.bagType = PKCSObjectIdentifiers.pkcs8ShroudedKeyBag;
        this.bagValue = new PKCS8EncryptedPrivateKeyInfoBuilder(privateKeyInfo).build(encryptor).toASN1Structure();
    }

    public PKCS12SafeBagBuilder(PrivateKeyInfo privateKeyInfo)
    {
        this.bagType = PKCSObjectIdentifiers.keyBag;
        this.bagValue = privateKeyInfo;
    }

    public PKCS12SafeBagBuilder(X509CertificateHolder certificate)
        throws IOException
    {
        this(certificate.toASN1Structure());
    }

    public PKCS12SafeBagBuilder(X509CRLHolder crl)
        throws IOException
    {
        this(crl.toASN1Structure());
    }

    public PKCS12SafeBagBuilder(Certificate certificate)
        throws IOException
    {
        this.bagType = PKCSObjectIdentifiers.certBag;
        this.bagValue = new CertBag(PKCSObjectIdentifiers.x509Certificate, new DEROctetString(certificate.getEncoded()));
    }

    public PKCS12SafeBagBuilder(CertificateList crl)
        throws IOException
    {
        this.bagType = PKCSObjectIdentifiers.crlBag;
        this.bagValue = new CertBag(PKCSObjectIdentifiers.x509Crl, new DEROctetString(crl.getEncoded()));
    }

    public org.bouncycastle.pkcs.PKCS12SafeBagBuilder addBagAttribute(ASN1ObjectIdentifier attrType, ASN1Encodable attrValue)
    {
        bagAttrs.add(new Attribute(attrType, new DERSet(attrValue)));

        return this;
    }

    public PKCS12SafeBag build()
    {
        return new PKCS12SafeBag(new SafeBag(bagType, bagValue, new DERSet(bagAttrs)));
    }
}