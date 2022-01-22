package com.github.zhenwei.pkix.est;

import com.github.zhenwei.core.util.Arrays;
import java.net.URL;


/**
 * Builder for basic EST requests
 */
public class ESTRequestBuilder
{
    private final String method;
    private URL url;

    private HttpUtil.Headers headers;
    ESTHijacker hijacker;
    ESTSourceConnectionListener listener;
    ESTClient client;
    private byte[] data;

    public ESTRequestBuilder(ESTRequest request)
    {

        this.method = request.method;
        this.url = request.url;
        this.listener = request.listener;
        this.data = request.data;
        this.hijacker = request.hijacker;
        this.headers = (HttpUtil.Headers)request.headers.clone();
        this.client = request.getClient();
    }

    public ESTRequestBuilder(String method, URL url)
    {
        this.method = method;
        this.url = url;
        this.headers = new HttpUtil.Headers();
    }

    public org.bouncycastle.est.ESTRequestBuilder withConnectionListener(ESTSourceConnectionListener listener)
    {
        this.listener = listener;

        return this;
    }

    public org.bouncycastle.est.ESTRequestBuilder withHijacker(ESTHijacker hijacker)
    {
        this.hijacker = hijacker;

        return this;
    }

    public org.bouncycastle.est.ESTRequestBuilder withURL(URL url)
    {
        this.url = url;

        return this;
    }

    public org.bouncycastle.est.ESTRequestBuilder withData(byte[] data)
    {
        this.data = Arrays.clone(data);

        return this;
    }

    public org.bouncycastle.est.ESTRequestBuilder addHeader(String key, String value)
    {
        headers.add(key, value);
        return this;
    }

    public org.bouncycastle.est.ESTRequestBuilder setHeader(String key, String value)
    {
        headers.set(key, value);
        return this;
    }

    public org.bouncycastle.est.ESTRequestBuilder withClient(ESTClient client)
    {
        this.client = client;
        return this;
    }

    public ESTRequest build()
    {
        return new ESTRequest(method, url, data, hijacker, listener, headers, client);
    }
}