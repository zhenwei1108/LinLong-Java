package com.github.zhenwei.pkix.operator;

import org.bouncycastle.operator.AADProcessor;
import org.bouncycastle.operator.InputDecryptor;

/**
 * Base interface for an input consuming AEAD Decryptor supporting associated text.
 */
public interface InputAEADDecryptor
    extends InputDecryptor, AADProcessor
{
}