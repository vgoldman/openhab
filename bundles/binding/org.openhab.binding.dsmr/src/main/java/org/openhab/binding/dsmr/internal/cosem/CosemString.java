/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.dsmr.internal.cosem;

import java.text.ParseException;

import org.openhab.core.library.types.StringType;

/**
 * CosemString represents a string value
 *
 * @author M. Volaart
 * @since 1.7.0
 */
public class CosemString extends CosemValue<StringType> {
    /**
     * Creates a new CosemString
     * 
     * @param unit
     *            the unit of the value
     * @param bindingSuffix
     *            the suffix to use for the DSMR binding identifier
     */
    public CosemString(String unit, String bindingSuffix) {
        super(unit, bindingSuffix);
    }

    /**
     * Parses a String value (that represents an integer) to an openHAB
     * StringType
     * 
     * @param cosemValue
     *            the value to parse
     * @return {@link StringType} on success
     * @throws ParseException
     *             if parsing failed
     */
    @Override
    protected StringType parse(String cosemValue) throws ParseException {
        return new StringType(cosemValue);
    }
}
