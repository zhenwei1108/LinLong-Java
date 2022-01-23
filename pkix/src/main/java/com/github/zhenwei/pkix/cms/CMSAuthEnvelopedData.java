package com.github.zhenwei.pkix.cms;


import cms.AttributeTable;
import cms.AuthEnvelopedData;
 
import cms.EncryptedContentInfo;
import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.ASN1Set;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.util.Arrays;
import com.github.zhenwei.core.util.Encodable;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;



/**
 * containing class for an CMS AuthEnveloped Data object
 */
public class CMSAuthEnvelopedData
    implements Encodable
{
    RecipientInformationStore recipientInfoStore;
    ContentInfo contentInfo;

    private OriginatorInformation  originatorInfo;
    private AlgorithmIdentifier authEncAlg;
    private ASN1Set authAttrs;
    private byte[]                 mac;
    private ASN1Set                unauthAttrs;

    public CMSAuthEnvelopedData(byte[] authEnvData) throws CMSException
    {
        this(CMSUtils.readContentInfo(authEnvData));
    }

    public CMSAuthEnvelopedData(InputStream authEnvData) throws CMSException
    {
        this(CMSUtils.readContentInfo(authEnvData));
    }

    public CMSAuthEnvelopedData(ContentInfo contentInfo) throws CMSException
    {
        this.contentInfo = contentInfo;

        AuthEnvelopedData authEnvData = AuthEnvelopedData.getInstance(contentInfo.getContent());

        if (authEnvData.getOriginatorInfo() != null)
        {
            this.originatorInfo = new OriginatorInformation(authEnvData.getOriginatorInfo());
        }

        //
        // read the recipients
        //
        ASN1Set recipientInfos = authEnvData.getRecipientInfos();

        //
        // read the auth-encrypted content info
        //
        final EncryptedContentInfo authEncInfo = authEnvData.getAuthEncryptedContentInfo();
        this.authEncAlg = authEncInfo.getContentEncryptionAlgorithm();

        this.mac = authEnvData.getMac().getOctets();

        CMSSecureReadable secureReadable = new CMSSecureReadable()
        {
            public ASN1ObjectIdentifier getContentType()
            {
                return authEncInfo.getContentType();
            }

            public InputStream getInputStream()
                throws IOException, CMSException
            {
                return new ByteArrayInputStream(
                    Arrays.concatenate(authEncInfo.getEncryptedContent().getOctets(), mac));
            }
        };

        this.authAttrs = authEnvData.getAuthAttrs();

        this.unauthAttrs = authEnvData.getUnauthAttrs();

        //
        // build the RecipientInformationStore
        //
        if (authAttrs != null)
        {
            this.recipientInfoStore = CMSEnvelopedHelper.buildRecipientInformationStore(
                recipientInfos, this.authEncAlg, secureReadable, new AuthAttributesProvider()
                {
                    public ASN1Set getAuthAttributes()
                    {
                        return authAttrs;
                    }

                    public boolean isAead()
                    {
                        return true;
                    }
                });
        }
        else
        {
            this.recipientInfoStore = CMSEnvelopedHelper.buildRecipientInformationStore(
                recipientInfos, this.authEncAlg, secureReadable);
        }
    }

    /**
     * Return the originator information associated with this message if present.
     *
     * @return OriginatorInformation, null if not present.
     */
    public OriginatorInformation getOriginatorInfo()
    {
        return originatorInfo;
    }

    /**
     * return a store of the intended recipients for this message
     */
    public RecipientInformationStore getRecipientInfos()
    {
        return recipientInfoStore;
    }

    /**
     * return a table of the authenticated attributes (as in those used to provide associated data) indexed by
     * the OID of the attribute.
     * @return the authenticated attributes.
     */
    public AttributeTable getAuthAttrs()
    {
        if (authAttrs == null)
        {
            return null;
        }

        return new AttributeTable(authAttrs);
    }

    /**
     * return a table of the unauthenticated attributes indexed by
     * the OID of the attribute.
     * @return the unauthenticated attributes.
     */
    public AttributeTable getUnauthAttrs()
    {
        if (unauthAttrs == null)
        {
            return null;
        }

        return new AttributeTable(unauthAttrs);
    }

    /**
     * Return the MAC value that was originally calculated for this AuthEnveloped data.
     * @return the MAC data associated with the stream.
     */
    public byte[] getMac()
    {
        return Arrays.clone(mac);
    }

    /**
     * return the ContentInfo
     */
    public ContentInfo toASN1Structure()
    {
        return contentInfo;
    }

    /**
     * return the ASN.1 encoded representation of this object.
     */
    public byte[] getEncoded()
        throws IOException
    {
        return contentInfo.getEncoded();
    }
}