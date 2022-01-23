package com.github.zhenwei.pkix.operator;


 

public interface SignatureAlgorithmIdentifierFinder
{
    /**
     * Find the signature algorithm identifier that matches with
     * the passed in signature algorithm name.
     *
     * @param sigAlgName the name of the signature algorithm of interest.
     * @return an algorithm identifier for the corresponding signature.
     */
    AlgorithmIdentifier find(String sigAlgName);
}