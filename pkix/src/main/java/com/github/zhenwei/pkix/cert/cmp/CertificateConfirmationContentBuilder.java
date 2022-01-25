package com.github.zhenwei.pkix.cert.cmp;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.pkix.util.asn1.cmp.CertConfirmContent;
import com.github.zhenwei.pkix.util.asn1.cmp.CertStatus;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.pkix.cert.X509CertificateHolder;
import  com.github.zhenwei.pkix.operator.DefaultDigestAlgorithmIdentifierFinder;
import  com.github.zhenwei.pkix.operator.DigestAlgorithmIdentifierFinder;
import  com.github.zhenwei.pkix.operator.DigestCalculator;
import  com.github.zhenwei.pkix.operator.DigestCalculatorProvider;
import  com.github.zhenwei.pkix.operator.OperatorCreationException;

public class CertificateConfirmationContentBuilder
{
    private DigestAlgorithmIdentifierFinder digestAlgFinder;
    private List acceptedCerts = new ArrayList();
    private List acceptedReqIds = new ArrayList();

    public CertificateConfirmationContentBuilder()
    {
        this(new DefaultDigestAlgorithmIdentifierFinder());
    }

    public CertificateConfirmationContentBuilder(DigestAlgorithmIdentifierFinder digestAlgFinder)
    {
        this.digestAlgFinder = digestAlgFinder;
    }
    
    public CertificateConfirmationContentBuilder addAcceptedCertificate(X509CertificateHolder certHolder, BigInteger certReqID)
    {
        acceptedCerts.add(certHolder);
        acceptedReqIds.add(certReqID);

        return this;
    }

    public CertificateConfirmationContent build(DigestCalculatorProvider digesterProvider)
        throws CMPException
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (int i = 0; i != acceptedCerts.size(); i++)
        {
            X509CertificateHolder certHolder = (X509CertificateHolder)acceptedCerts.get(i);
            BigInteger reqID = (BigInteger)acceptedReqIds.get(i);

            AlgorithmIdentifier digAlg = digestAlgFinder.find(certHolder.toASN1Structure().getSignatureAlgorithm());
            if (digAlg == null)
            {
                throw new CMPException("cannot find algorithm for digest from signature");
            }

            DigestCalculator digester;

            try
            {
                digester = digesterProvider.get(digAlg);
            }
            catch (OperatorCreationException e)
            {
                throw new CMPException("unable to create digest: " + e.getMessage(), e);
            }

            CMPUtil.derEncodeToStream(certHolder.toASN1Structure(), digester.getOutputStream());

            v.add(new CertStatus(digester.getDigest(), reqID));
        }

        return new CertificateConfirmationContent(CertConfirmContent.getInstance(new DERSequence(v)), digestAlgFinder);
    }

}