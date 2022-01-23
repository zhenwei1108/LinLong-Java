package com.github.zhenwei.pkix.operator;


import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
 

public interface DigestAlgorithmIdentifierFinder
{
    /**
     * Find the digest algorithm identifier that matches with
     * the passed in signature algorithm identifier.
     *
     * @param sigAlgId the signature algorithm of interest.
     * @return an algorithm identifier for the corresponding digest.
     */
    AlgorithmIdentifier find(AlgorithmIdentifier sigAlgId);

    /**
     * Find the algorithm identifier that matches with
     * the passed in digest name.
     *
     * @param digestOid the name of the digest algorithm of interest.
     * @return an algorithm identifier for the digest signature.
     */
    AlgorithmIdentifier find(ASN1ObjectIdentifier digestOid);

    /**
     * Find the algorithm identifier that matches with
     * the passed in digest name.
     *
     * @param digAlgName the name of the digest algorithm of interest.
     * @return an algorithm identifier for the digest signature.
     */
    AlgorithmIdentifier find(String digAlgName);
}