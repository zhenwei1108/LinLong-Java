package com.github.zhenwei.core.util;

import java.util.Collection;
import org.bouncycastle.util.StreamParsingException;

public interface StreamParser
{
    Object read() throws StreamParsingException;

    Collection readAll() throws StreamParsingException;
}