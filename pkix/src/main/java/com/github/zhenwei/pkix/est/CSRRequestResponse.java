package com.github.zhenwei.pkix.est;

import org.bouncycastle.est.CSRAttributesResponse;
import org.bouncycastle.est.Source;

/**
 * Holder class for a response containing the details making up /csrattrs response.
 */
public class CSRRequestResponse
{
    private final CSRAttributesResponse attributesResponse;
    private final Source source;

    public CSRRequestResponse(CSRAttributesResponse attributesResponse, Source session)
    {
        this.attributesResponse = attributesResponse;
        this.source = session;
    }

    public boolean hasAttributesResponse()
    {
        return attributesResponse != null;
    }

    public CSRAttributesResponse getAttributesResponse()
    {
        if (attributesResponse == null)
        {
            throw new IllegalStateException("Response has no CSRAttributesResponse.");
        }
        return attributesResponse;
    }

    public Object getSession()
    {
        return source.getSession();
    }

    public Source getSource()
    {
        return source;
    }
}