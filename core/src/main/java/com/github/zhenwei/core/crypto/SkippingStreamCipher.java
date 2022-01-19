package com.github.zhenwei.core.crypto;

import org.bouncycastle.crypto.SkippingCipher;
import org.bouncycastle.crypto.StreamCipher;

/**
 * General interface for a stream cipher that supports skipping.
 */
public interface SkippingStreamCipher
    extends StreamCipher, SkippingCipher
{
}