/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.samsungac;

import org.openhab.binding.samsungac.internal.CommandEnum;
import org.openhab.core.binding.BindingProvider;

/**
 * This interface is implemented by classes that can provide mapping information
 * between openHAB items and Samsung AC devices.
 *
 * @author Stein Tore Tøsse
 * @since 1.6.0
 */
public interface SamsungAcBindingProvider extends BindingProvider {
    String getAirConditionerInstance(String itemname);

    CommandEnum getProperty(String itemname);

    String getItemName(String acName, CommandEnum property);
}
