package com.github.zhenwei.pkix.cms;









import DLSet;
import cms.AttributeTable;
import cms.AuthEnvelopedData;
import cms.CMSObjectIdentifiers;
import cms.ContentInfo;
import cms.EncryptedContentInfo;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Collections;
import java.util.Iterator;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.OutputAEADEncryptor;

public class CMSAuthEnvelopedDataGenerator
    extends CMSAuthEnvelopedGenerator
{
    /**
     * base constructor
     */
    public CMSAuthEnvelopedDataGenerator()
    {
    }

    private CMSAuthEnvelopedData doGenerate(
        CMSTypedData content,
        OutputAEADEncryptor contentEncryptor)
        throws CMSException
    {
        ASN1EncodableVector recipientInfos = new ASN1EncodableVector();
        AlgorithmIdentifier encAlgId;
        ASN1OctetString encContent;

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ASN1Set authenticatedAttrSet = null;
        try
        {
            OutputStream cOut = contentEncryptor.getOutputStream(bOut);

            content.write(cOut);

            if (authAttrsGenerator != null)
            {
                AttributeTable attrTable = authAttrsGenerator.getAttributes(Collections.emptyMap());

                authenticatedAttrSet = new DERSet(attrTable.toASN1EncodableVector());

                contentEncryptor.getAADStream().write(authenticatedAttrSet.getEncoded(ASN1Encoding.DER));
            }

            cOut.close();
        }
        catch (IOException e)
        {
            throw new CMSException("unable to process authenticated content: " + e.getMessage(), e);
        }

        byte[] encryptedContent = bOut.toByteArray();
        byte[] mac = contentEncryptor.getMAC();

        encAlgId = contentEncryptor.getAlgorithmIdentifier();

        encContent = new BEROctetString(encryptedContent);

        GenericKey encKey = contentEncryptor.getKey();

        for (Iterator it = recipientInfoGenerators.iterator(); it.hasNext();)
        {
            RecipientInfoGenerator recipient = (RecipientInfoGenerator)it.next();

            recipientInfos.add(recipient.generate(encKey));
        }

        EncryptedContentInfo eci = new EncryptedContentInfo(
                        content.getContentType(),
                        encAlgId,
                        encContent);

        ASN1Set unprotectedAttrSet = null;
        if (unauthAttrsGenerator != null)
        {
            AttributeTable attrTable = unauthAttrsGenerator.getAttributes(Collections.emptyMap());

            unprotectedAttrSet = new DLSet(attrTable.toASN1EncodableVector());
        }

        ContentInfo contentInfo = new ContentInfo(
                CMSObjectIdentifiers.authEnvelopedData,
                new AuthEnvelopedData(originatorInfo, new DERSet(recipientInfos), eci, authenticatedAttrSet, new DEROctetString(mac), unprotectedAttrSet));

        return new CMSAuthEnvelopedData(contentInfo);
    }

    /**
     * generate an auth-enveloped object that contains an CMS Enveloped Data
     * object using the given provider.
     *
     * @param content the content to be encrypted
     * @param contentEncryptor the symmetric key based encryptor to encrypt the content with.
     */
    public CMSAuthEnvelopedData generate(
        CMSTypedData content,
        OutputAEADEncryptor contentEncryptor)
        throws CMSException
    {
        return doGenerate(content, contentEncryptor);
    }
}