package com.github.zhenwei.core.asn1.x509;

import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.NameConstraintValidatorException;

public interface NameConstraintValidator
{
    void checkPermitted(GeneralName name)
        throws NameConstraintValidatorException;

    void checkExcluded(GeneralName name)
            throws NameConstraintValidatorException;

    void intersectPermittedSubtree(GeneralSubtree permitted);

    void intersectPermittedSubtree(GeneralSubtree[] permitted);

    void intersectEmptyPermittedSubtree(int nameType);

    void addExcludedSubtree(GeneralSubtree subtree);
}