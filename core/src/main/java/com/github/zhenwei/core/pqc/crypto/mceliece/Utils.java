package com.github.zhenwei.core.pqc.crypto.mceliece;


import SHA1Digest;
import SHA224Digest;
import SHA256Digest;
import SHA384Digest;
import SHA512Digest;
import com.github.zhenwei.core.crypto.Digest;

class Utils
{
    static Digest getDigest(String digestName)
    {
        if (digestName.equals("SHA-1"))
        {
            return new SHA1Digest();
        }
        if (digestName.equals("SHA-224"))
        {
            return new SHA224Digest();
        }
        if (digestName.equals("SHA-256"))
        {
            return new SHA256Digest();
        }
        if (digestName.equals("SHA-384"))
        {
            return new SHA384Digest();
        }
        if (digestName.equals("SHA-512"))
        {
            return new SHA512Digest();
        }

        throw new IllegalArgumentException("unrecognised digest algorithm: " + digestName);
    }
}