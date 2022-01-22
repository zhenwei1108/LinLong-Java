package com.github.zhenwei.sdk.util.asn1.smime;


import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;


public interface SMIMEAttributes
{
    ASN1ObjectIdentifier smimeCapabilities = PKCSObjectIdentifiers.pkcs_9_at_smimeCapabilities;
    ASN1ObjectIdentifier  encrypKeyPref = PKCSObjectIdentifiers.id_aa_encrypKeyPref;
}