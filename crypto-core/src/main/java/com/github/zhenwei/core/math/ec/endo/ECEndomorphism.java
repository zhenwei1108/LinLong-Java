package com.github.zhenwei.core.math.ec.endo;

import com.github.zhenwei.core.math.ec.ECPointMap;

public interface ECEndomorphism {

  ECPointMap getPointMap();

  boolean hasEfficientPointMap();
}