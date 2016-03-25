/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.powermax;

import java.util.ArrayList;
import java.util.List;

import org.openhab.binding.powermax.internal.PowerMaxSelectorType;
import org.openhab.core.binding.BindingConfig;
import org.openhab.core.items.Item;
import org.openhab.core.types.State;

/**
 * Binding Configuration class. Represents a binding configuration in the items
 * file to a PowerMax Alarm system
 *
 * @author lolodomo
 * @since 1.9.0
 */
public class PowerMaxBindingConfig implements BindingConfig {

    private PowerMaxSelectorType selectorType;
    private String selectorParam;
    private List<Class<? extends State>> acceptedDataTypes;

    public PowerMaxBindingConfig(PowerMaxSelectorType selectorType, String selectorParam, Item item) {
        this.selectorType = selectorType;
        this.selectorParam = selectorParam;
        this.acceptedDataTypes = new ArrayList<Class<? extends State>>(item.getAcceptedDataTypes());
    }

    /**
     * @return the selector type
     */
    public PowerMaxSelectorType getSelectorType() {
        return selectorType;
    }

    /**
     * @return the selector parameter, or null if no parameter
     */
    public String getSelectorParam() {
        return selectorParam;
    }

    /**
     * @return the list of accepted data types (states)
     */
    public List<Class<? extends State>> getAcceptedDataTypes() {
        return acceptedDataTypes;
    }

    /**
     * @return the selector parameter as an integer, or null if no parameter or
     *         if the parameter is not an integer
     */
    public Integer getSelectorIntParam() {
        Integer number = null;
        if (selectorParam != null) {
            try {
                number = Integer.parseInt(selectorParam);
            } catch (NumberFormatException numberFormatException) {
                number = null;
            }
        }
        return number;
    }
}
