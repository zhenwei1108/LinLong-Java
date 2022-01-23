package com.github.zhenwei.core.math.field;


public interface PolynomialExtensionField extends ExtensionField {

  Polynomial getMinimalPolynomial();
}