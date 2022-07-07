package com.github.zhenwei.core.math.field;

public interface ExtensionField extends FiniteField {

  FiniteField getSubfield();

  int getDegree();
}