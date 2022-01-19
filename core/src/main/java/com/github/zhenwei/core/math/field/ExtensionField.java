package com.github.zhenwei.core.math.field;

import org.bouncycastle.math.field.FiniteField;

public interface ExtensionField extends FiniteField
{
    FiniteField getSubfield();

    int getDegree();
}