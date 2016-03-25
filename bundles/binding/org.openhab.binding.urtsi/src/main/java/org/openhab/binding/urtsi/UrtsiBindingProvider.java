/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.urtsi;

import org.openhab.core.autoupdate.AutoUpdateBindingProvider;

/**
 * @author Oliver Libutzki
 * @since 1.3.0
 *
 */
public interface UrtsiBindingProvider extends AutoUpdateBindingProvider {

    String getDeviceId(String itemName);

    int getChannel(String itemName);

    int getAddress(String itemName);
}
