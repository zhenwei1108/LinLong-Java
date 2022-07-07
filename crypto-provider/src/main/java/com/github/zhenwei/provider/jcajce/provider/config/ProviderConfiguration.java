package com.github.zhenwei.provider.jcajce.provider.config;

import com.github.zhenwei.provider.jce.spec.ECParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.util.Map;
import java.util.Set;
import javax.crypto.spec.DHParameterSpec;

public interface ProviderConfiguration {

  ECParameterSpec getEcImplicitlyCa();

  DHParameterSpec getDHDefaultParameters(int keySize);

  DSAParameterSpec getDSADefaultParameters(int keySize);

  Set getAcceptableNamedCurves();

  Map getAdditionalECParameters();
}