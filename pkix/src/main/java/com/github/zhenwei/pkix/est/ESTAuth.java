package com.github.zhenwei.pkix.est;


import org.bouncycastle.est.ESTRequestBuilder;

/**
 * Base interface for an object with adds HTTP Auth attributes to an ESTRequest
 */
public interface ESTAuth
{
    /**
     * Add the Auth attributes to the passed in request builder.
     *
     * @param reqBldr the builder for the request needing the Auth attributes.
     */
    void applyAuth(ESTRequestBuilder reqBldr);
}