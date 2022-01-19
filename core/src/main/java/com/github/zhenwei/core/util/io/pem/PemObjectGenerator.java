package com.github.zhenwei.core.util.io.pem;

import org.bouncycastle.util.io.pem.PemGenerationException;
import org.bouncycastle.util.io.pem.PemObject;

/**
 * Base interface for generators of PEM objects.
 */
public interface PemObjectGenerator
{
    /**
     * Generate a PEM object.
     *
     * @return the generated object.
     * @throws PemGenerationException on failure.
     */
    PemObject generate()
        throws PemGenerationException;
}