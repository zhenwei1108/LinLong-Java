package com.github.zhenwei.pkix.cert.crmf;


 
import ExtensionsGenerator;
import Time;

import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.DERNull;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.asn1.DERTaggedObject;
import  SubjectPublicKeyInfo;
import crmf.AttributeTypeAndValue;
import crmf.CertReqMsg;
import crmf.CertRequest;
import crmf.CertTemplate;
import crmf.CertTemplateBuilder;
import crmf.OptionalValidity;
import crmf.PKMACValue;
import crmf.POPOPrivKey;
import crmf.ProofOfPossession;
import crmf.SubsequentMessage;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import org.bouncycastle.cert.CertIOException;


public class CertificateRequestMessageBuilder
{
    private final BigInteger certReqId;

    private ExtensionsGenerator extGenerator;
    private CertTemplateBuilder templateBuilder;
    private List controls;
    private ContentSigner popSigner;
    private PKMACBuilder pkmacBuilder;
    private char[] password;
    private GeneralName sender;
    private int popoType = ProofOfPossession.TYPE_KEY_ENCIPHERMENT;
    private POPOPrivKey popoPrivKey;
    private ASN1Null popRaVerified;
    private PKMACValue agreeMAC;

    public CertificateRequestMessageBuilder(BigInteger certReqId)
    {
        this.certReqId = certReqId;

        this.extGenerator = new ExtensionsGenerator();
        this.templateBuilder = new CertTemplateBuilder();
        this.controls = new ArrayList();
    }

    public org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder setPublicKey(
        SubjectPublicKeyInfo publicKey)
    {
        if (publicKey != null)
        {
            templateBuilder.setPublicKey(publicKey);
        }

        return this;
    }

    public org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder setIssuer(X500Name issuer)
    {
        if (issuer != null)
        {
            templateBuilder.setIssuer(issuer);
        }

        return this;
    }

    public org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder setSubject(X500Name subject)
    {
        if (subject != null)
        {
            templateBuilder.setSubject(subject);
        }

        return this;
    }

    public org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder setSerialNumber(BigInteger serialNumber)
    {
        if (serialNumber != null)
        {
            templateBuilder.setSerialNumber(new ASN1Integer(serialNumber));
        }

        return this;
    }

    /**
     * Request a validity period for the certificate. Either, but not both, of the date parameters may be null.
     *
     * @param notBeforeDate not before date for certificate requested.
     * @param notAfterDate not after date for the certificate requested.
     *
     * @return the current builder.
     */
    public org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder setValidity(Date notBeforeDate, Date notAfterDate)
    {
        templateBuilder.setValidity(new OptionalValidity(createTime(notBeforeDate), createTime(notAfterDate)));

        return this;
    }

    private Time createTime(Date date)
    {
        if (date != null)
        {
            return new Time(date);
        }

        return null;
    }

    public org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder addExtension(
        ASN1ObjectIdentifier oid,
        boolean              critical,
        ASN1Encodable value)
        throws CertIOException
    {
        CRMFUtil.addExtension(extGenerator, oid, critical, value);

        return this;
    }

    public org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder addExtension(
        ASN1ObjectIdentifier oid,
        boolean              critical,
        byte[]               value)
    {
        extGenerator.addExtension(oid, critical, value);

        return this;
    }

    public org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder addControl(Control control)
    {
        controls.add(control);

        return this;
    }

    public org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder setProofOfPossessionSigningKeySigner(ContentSigner popSigner)
    {
        if (popoPrivKey != null || popRaVerified != null || agreeMAC != null)
        {
            throw new IllegalStateException("only one proof of possession allowed");
        }

        this.popSigner = popSigner;

        return this;
    }

    public org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder setProofOfPossessionSubsequentMessage(SubsequentMessage msg)
    {
        if (popSigner != null || popRaVerified != null || agreeMAC != null)
        {
            throw new IllegalStateException("only one proof of possession allowed");
        }

        this.popoType = ProofOfPossession.TYPE_KEY_ENCIPHERMENT;
        this.popoPrivKey = new POPOPrivKey(msg);

        return this;
    }

    public org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder setProofOfPossessionSubsequentMessage(int type, SubsequentMessage msg)
    {
        if (popSigner != null || popRaVerified != null || agreeMAC != null)
        {
            throw new IllegalStateException("only one proof of possession allowed");
        }
        if (type != ProofOfPossession.TYPE_KEY_ENCIPHERMENT && type != ProofOfPossession.TYPE_KEY_AGREEMENT)
        {
            throw new IllegalArgumentException("type must be ProofOfPossession.TYPE_KEY_ENCIPHERMENT || ProofOfPossession.TYPE_KEY_AGREEMENT");
        }

        this.popoType = type;
        this.popoPrivKey = new POPOPrivKey(msg);

        return this;
    }

    public org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder setProofOfPossessionAgreeMAC(PKMACValue macValue)
    {
        if (popSigner != null || popRaVerified != null || popoPrivKey != null)
        {
            throw new IllegalStateException("only one proof of possession allowed");
        }

        this.agreeMAC = macValue;

        return this;
    }

    public org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder setProofOfPossessionRaVerified()
    {
        if (popSigner != null || popoPrivKey != null)
        {
            throw new IllegalStateException("only one proof of possession allowed");
        }

        this.popRaVerified = DERNull.INSTANCE;

        return this;
    }

    public org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder setAuthInfoPKMAC(PKMACBuilder pkmacBuilder, char[] password)
    {
        this.pkmacBuilder = pkmacBuilder;
        this.password = password;

        return this;
    }

    public org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder setAuthInfoSender(X500Name sender)
    {
        return setAuthInfoSender(new GeneralName(sender));
    }

    public org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder setAuthInfoSender(GeneralName sender)
    {
        this.sender = sender;

        return this;
    }

    public CertificateRequestMessage build()
        throws CRMFException
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(certReqId));

        if (!extGenerator.isEmpty())
        {
            templateBuilder.setExtensions(extGenerator.generate());
        }

        v.add(templateBuilder.build());

        if (!controls.isEmpty())
        {
            ASN1EncodableVector controlV = new ASN1EncodableVector();

            for (Iterator it = controls.iterator(); it.hasNext();)
            {
                Control control = (Control)it.next();

                controlV.add(new AttributeTypeAndValue(control.getType(), control.getValue()));
            }

            v.add(new DERSequence(controlV));
        }

        CertRequest request = CertRequest.getInstance(new DERSequence(v));

        v = new ASN1EncodableVector();

        v.add(request);

        if (popSigner != null)
        {
            CertTemplate template = request.getCertTemplate();

            if (template.getSubject() == null || template.getPublicKey() == null)
            {
                SubjectPublicKeyInfo pubKeyInfo = request.getCertTemplate().getPublicKey();
                ProofOfPossessionSigningKeyBuilder builder = new ProofOfPossessionSigningKeyBuilder(pubKeyInfo);

                if (sender != null)
                {
                    builder.setSender(sender);
                }
                else
                {
                    PKMACValueGenerator pkmacGenerator = new PKMACValueGenerator(pkmacBuilder);

                    builder.setPublicKeyMac(pkmacGenerator, password);
                }

                v.add(new ProofOfPossession(builder.build(popSigner)));
            }
            else
            {
                ProofOfPossessionSigningKeyBuilder builder = new ProofOfPossessionSigningKeyBuilder(request);

                v.add(new ProofOfPossession(builder.build(popSigner)));
            }
        }
        else if (popoPrivKey != null)
        {
            v.add(new ProofOfPossession(popoType, popoPrivKey));
        }
        else if (agreeMAC != null)
        {
            v.add(new ProofOfPossession(ProofOfPossession.TYPE_KEY_AGREEMENT,
                    POPOPrivKey.getInstance(new DERTaggedObject(false, POPOPrivKey.agreeMAC, agreeMAC))));

        }
        else if (popRaVerified != null)
        {
            v.add(new ProofOfPossession());
        }

        return new CertificateRequestMessage(CertReqMsg.getInstance(new DERSequence(v)));
    }
}