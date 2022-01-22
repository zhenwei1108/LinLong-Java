package com.github.zhenwei.pkix.cert.crmf;





import crmf.CRMFObjectIdentifiers;

/**
 * Carrier for an authenticator control.
 */
public class AuthenticatorControl
    implements Control
{
    private static final ASN1ObjectIdentifier type = CRMFObjectIdentifiers.id_regCtrl_authenticator;

    private final ASN1UTF8String token;

    /**
     * Basic constructor - build from a UTF-8 string representing the token.
     *
     * @param token UTF-8 string representing the token.
     */
    public AuthenticatorControl(ASN1UTF8String token)
    {
        this.token = token;
    }

    /**
     * Basic constructor - build from a string representing the token.
     *
     * @param token string representing the token.
     */
    public AuthenticatorControl(String token)
    {
        this.token = new DERUTF8String(token);
    }

    /**
     * Return the type of this control.
     *
     * @return CRMFObjectIdentifiers.id_regCtrl_authenticator
     */
    public ASN1ObjectIdentifier getType()
    {
        return type;
    }

    /**
     * Return the token associated with this control (a UTF8String).
     *
     * @return a UTF8String.
     */
    public ASN1Encodable getValue()
    {
        return token;
    }
}