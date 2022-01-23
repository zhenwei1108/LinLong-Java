package com.github.zhenwei.pkix.cert.ocsp;




import DERGeneralizedTime;
import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Encoding;
import com.github.zhenwei.core.asn1.DERBitString;
import com.github.zhenwei.core.asn1.DERNull;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.asn1.x509.SubjectPublicKeyInfo;
import com.github.zhenwei.pkix.cert.X509CertificateHolder;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import CertStatus;



import org.bouncycastle.operator.DigestCalculator;

/**
 * Generator for basic OCSP response objects.
 */
public class BasicOCSPRespBuilder
{
    private List            list = new ArrayList();
    private Extensions  responseExtensions = null;
    private RespID          responderID;

    private class ResponseObject
    {
        CertificateID         certId;
        CertStatus            certStatus;
        ASN1GeneralizedTime   thisUpdate;
        ASN1GeneralizedTime   nextUpdate;
        Extensions        extensions;

        public ResponseObject(
            CertificateID     certId,
            CertificateStatus certStatus,
            Date              thisUpdate,
            Date              nextUpdate,
            Extensions    extensions)
        {
            this.certId = certId;

            if (certStatus == null)
            {
                this.certStatus = new CertStatus();
            }
            else if (certStatus instanceof UnknownStatus)
            {
                this.certStatus = new CertStatus(2, DERNull.INSTANCE);
            }
            else
            {
                RevokedStatus rs = (RevokedStatus)certStatus;

                if (rs.hasRevocationReason())
                {
                    this.certStatus = new CertStatus(
                                            new RevokedInfo(new ASN1GeneralizedTime(rs.getRevocationTime()), CRLReason.lookup(rs.getRevocationReason())));
                }
                else
                {
                    this.certStatus = new CertStatus(
                                            new RevokedInfo(new ASN1GeneralizedTime(rs.getRevocationTime()), null));
                }
            }

            this.thisUpdate = new DERGeneralizedTime(thisUpdate);

            if (nextUpdate != null)
            {
                this.nextUpdate = new DERGeneralizedTime(nextUpdate);
            }
            else
            {
                this.nextUpdate = null;
            }

            this.extensions = extensions;
        }

        public SingleResponse toResponse()
            throws Exception
        {
            return new SingleResponse(certId.toASN1Primitive(), certStatus, thisUpdate, nextUpdate, extensions);
        }
    }

    /**
     * basic constructor
     */
    public BasicOCSPRespBuilder(
        RespID  responderID)
    {
        this.responderID = responderID;
    }

    /**
     * construct with the responderID to be the SHA-1 keyHash of the passed in public key.
     *
     * @param key the key info of the responder public key.
     * @param digCalc  a SHA-1 digest calculator
     */
    public BasicOCSPRespBuilder(
        SubjectPublicKeyInfo key,
        DigestCalculator     digCalc)
        throws OCSPException
    {
        this.responderID = new RespID(key, digCalc);
    }

    /**
     * Add a response for a particular Certificate ID.
     *
     * @param certID certificate ID details
     * @param certStatus status of the certificate - null if okay
     */
    public org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder addResponse(
        CertificateID       certID,
        CertificateStatus   certStatus)
    {
        this.addResponse(certID, certStatus, new Date(), null, null);

        return this;
    }

    /**
     * Add a response for a particular Certificate ID.
     *
     * @param certID certificate ID details
     * @param certStatus status of the certificate - null if okay
     * @param singleExtensions optional extensions
     */
    public org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder addResponse(
        CertificateID       certID,
        CertificateStatus   certStatus,
        Extensions          singleExtensions)
    {
        this.addResponse(certID, certStatus, new Date(), null, singleExtensions);

        return this;
    }

    /**
     * Add a response for a particular Certificate ID.
     *
     * @param certID certificate ID details
     * @param nextUpdate date when next update should be requested
     * @param certStatus status of the certificate - null if okay
     * @param singleExtensions optional extensions
     */
    public org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder addResponse(
        CertificateID       certID,
        CertificateStatus   certStatus,
        Date                nextUpdate,
        Extensions          singleExtensions)
    {
        this.addResponse(certID, certStatus, new Date(), nextUpdate, singleExtensions);

        return this;
    }

    /**
     * Add a response for a particular Certificate ID.
     *
     * @param certID certificate ID details
     * @param thisUpdate date this response was valid on
     * @param nextUpdate date when next update should be requested
     * @param certStatus status of the certificate - null if okay
     */
    public org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder addResponse(
        CertificateID       certID,
        CertificateStatus   certStatus,
        Date                thisUpdate,
        Date                nextUpdate)
    {
        this.addResponse(certID, certStatus, thisUpdate, nextUpdate, null);

        return this;
    }

    /**
     * Add a response for a particular Certificate ID.
     *
     * @param certID certificate ID details
     * @param thisUpdate date this response was valid on
     * @param nextUpdate date when next update should be requested
     * @param certStatus status of the certificate - null if okay
     * @param singleExtensions optional extensions
     */
    public org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder addResponse(
        CertificateID       certID,
        CertificateStatus   certStatus,
        Date                thisUpdate,
        Date                nextUpdate,
        Extensions          singleExtensions)
    {
        list.add(new ResponseObject(certID, certStatus, thisUpdate, nextUpdate, singleExtensions));

        return this;
    }

    /**
     * Set the extensions for the response.
     *
     * @param responseExtensions the extension object to carry.
     */
    public org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder setResponseExtensions(
        Extensions  responseExtensions)
    {
        this.responseExtensions = responseExtensions;

        return this;
    }

    public BasicOCSPResp build(
        ContentSigner signer,
        X509CertificateHolder[]   chain,
        Date                producedAt)
        throws OCSPException
    {
        Iterator    it = list.iterator();

        ASN1EncodableVector responses = new ASN1EncodableVector();

        while (it.hasNext())
        {
            try
            {
                responses.add(((ResponseObject)it.next()).toResponse());
            }
            catch (Exception e)
            {
                throw new OCSPException("exception creating Request", e);
            }
        }

        ResponseData  tbsResp = new ResponseData(responderID.toASN1Primitive(), new ASN1GeneralizedTime(producedAt), new DERSequence(responses), responseExtensions);
        DERBitString bitSig;

        try
        {
            OutputStream sigOut = signer.getOutputStream();

            sigOut.write(tbsResp.getEncoded(ASN1Encoding.DER));
            sigOut.close();

            bitSig = new DERBitString(signer.getSignature());
        }
        catch (Exception e)
        {
            throw new OCSPException("exception processing TBSRequest: " + e.getMessage(), e);
        }

        AlgorithmIdentifier sigAlgId = signer.getAlgorithmIdentifier();

        DERSequence chainSeq = null;
        if (chain != null && chain.length > 0)
        {
            ASN1EncodableVector v = new ASN1EncodableVector();

            for (int i = 0; i != chain.length; i++)
            {
                v.add(chain[i].toASN1Structure());
            }

            chainSeq = new DERSequence(v);
        }

        return new BasicOCSPResp(new BasicOCSPResponse(tbsResp, sigAlgId, bitSig, chainSeq));
    }
}