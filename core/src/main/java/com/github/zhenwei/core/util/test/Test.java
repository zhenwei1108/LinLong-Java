package com.github.zhenwei.core.util.test;

import org.bouncycastle.util.test.TestResult;

public interface Test
{
    String getName();

    TestResult perform();
}