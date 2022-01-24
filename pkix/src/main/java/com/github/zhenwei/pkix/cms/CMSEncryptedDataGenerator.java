package com.github.zhenwei.pkix.cms;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Collections;
import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.ASN1Set;
import com.github.zhenwei.core.asn1.BEROctetString;
import com.github.zhenwei.core.asn1.BERSet;
import com.github.zhenwei.pkix.util.asn1.cmsAttributeTable;
import com.github.zhenwei.pkix.util.asn1.cmsCMSObjectIdentifiers;
import com.github.zhenwei.pkix.util.asn1.cmsContentInfo;
import com.github.zhenwei.pkix.util.asn1.cmsEncryptedContentInfo;
import com.github.zhenwei.pkix.util.asn1.cmsEncryptedData;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import  com.github.zhenwei.pkix.operator.OutputEncryptor;

/**
 * General class for generating a CMS encrypted-data message.
 *
 * A simple example of usage.
 *
 * <pre>
 *       CMSTypedData msg     = new CMSProcessableByteArray("Hello World!".getBytes());
 *
 *       CMSEncryptedDataGenerator edGen = new CMSEncryptedDataGenerator();
 *
 *       CMSEncryptedData ed = edGen.generate(
 *                                       msg,
 *                                       new JceCMSContentEncryptorBuilder(CMSAlgorithm.DES_EDE3_CBC)
 *                                              .setProvider("BC").build());
 *
 * </pre>
 */
public class CMSEncryptedDataGenerator
    extends CMSEncryptedGenerator
{
    /**
     * base constructor
     */
    public CMSEncryptedDataGenerator()
    {
    }

    private CMSEncryptedData doGenerate(
        CMSTypedData content,
        OutputEncryptor contentEncryptor)
        throws CMSException
    {
        AlgorithmIdentifier     encAlgId;
        ASN1OctetString         encContent;

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        try
        {
            OutputStream cOut = contentEncryptor.getOutputStream(bOut);

            content.write(cOut);

            cOut.close();
        }
        catch (IOException e)
        {
            throw new CMSException("");
        }

        byte[] encryptedContent = bOut.toByteArray();

        encAlgId = contentEncryptor.getAlgorithmIdentifier();

        encContent = new BEROctetString(encryptedContent);

        EncryptedContentInfo  eci = new EncryptedContentInfo(
                        content.getContentType(),
                        encAlgId,
                        encContent);

        ASN1Set unprotectedAttrSet = null;
        if (unprotectedAttributeGenerator != null)
        {
            AttributeTable attrTable = unprotectedAttributeGenerator.getAttributes(Collections.EMPTY_MAP);

            unprotectedAttrSet = new BERSet(attrTable.toASN1EncodableVector());
        }

        ContentInfo contentInfo = new ContentInfo(
                CMSObjectIdentifiers.encryptedData,
                new EncryptedData(eci, unprotectedAttrSet));

        return new CMSEncryptedData(contentInfo);
    }

    /**
     * generate an encrypted object that contains an CMS Encrypted Data structure.
     *
     * @param content the content to be encrypted
     * @param contentEncryptor the symmetric key based encryptor to encrypt the content with.
     */
    public CMSEncryptedData generate(
        CMSTypedData content,
        OutputEncryptor contentEncryptor)
        throws CMSException
    {
        return doGenerate(content, contentEncryptor);
    }
}