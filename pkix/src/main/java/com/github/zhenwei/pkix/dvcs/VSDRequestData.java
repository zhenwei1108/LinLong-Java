package com.github.zhenwei.pkix.dvcs;

import com.github.zhenwei.pkix.util.asn1.dvcs.Data;
import com.github.zhenwei.pkix.cms.CMSException;
import com.github.zhenwei.pkix.cms.CMSSignedData;

/**
 * Data piece of DVCS request to VSD service (Verify Signed Document).
 * It contains VSD-specific selector interface.
 * Note: the request should contain CMS SignedData object as message.
 * <p>
 * This objects are constructed internally,
 * to build DVCS request to VSD service use VSDRequestBuilder.
 * </p>
 */
public class VSDRequestData
    extends DVCSRequestData
{
    private CMSSignedData doc;

    VSDRequestData(Data data)
        throws DVCSConstructionException
    {
        super(data);
        initDocument();
    }

    private void initDocument()
        throws DVCSConstructionException
    {
        if (doc == null)
        {
            if (data.getMessage() == null)
            {
                throw new DVCSConstructionException("DVCSRequest.data.message should be specified for VSD service");
            }
            try
            {
                doc = new CMSSignedData(data.getMessage().getOctets());
            }
            catch (CMSException e)
            {
                throw new DVCSConstructionException("Can't read CMS SignedData from input", e);
            }
        }
    }

    /**
     * Get contained message (data to be certified).
     *
     * @return the contained message.
     */
    public byte[] getMessage()
    {
        return data.getMessage().getOctets();
    }

    /**
     * Get the CMS SignedData object represented by the encoded message.
     *
     * @return the parsed contents of the contained message as a CMS SignedData object.
     */
    public CMSSignedData getParsedMessage()
    {
        return doc;
    }
}