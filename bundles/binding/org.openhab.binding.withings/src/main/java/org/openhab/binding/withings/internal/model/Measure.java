/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.withings.internal.model;

/**
 * Java object for response of Withings API.
 *
 * @see http://www.withings.com/de/api#bodymetrics
 * @author Dennis Nobel
 * @since 1.5.0
 */
public class Measure {

    public MeasureType type;
    public int unit;
    public int value;

    public float getActualValue() {
        return (float) (value * Math.pow(10, unit));
    }

}
