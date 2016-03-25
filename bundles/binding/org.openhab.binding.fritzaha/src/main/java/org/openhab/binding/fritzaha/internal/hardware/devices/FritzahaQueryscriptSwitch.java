/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.fritzaha.internal.hardware.devices;

import org.openhab.binding.fritzaha.internal.hardware.FritzahaWebInterface;
import org.openhab.binding.fritzaha.internal.hardware.callbacks.FritzahaQueryscriptUpdateSwitchCallback;
import org.openhab.binding.fritzaha.internal.hardware.callbacks.FritzahaReauthCallback;
import org.openhab.binding.fritzaha.internal.hardware.interfaces.FritzahaSwitchedOutlet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Switch in outlet addressed via query script
 *
 * @author Christian Brauers
 * @since 1.3.0
 */
public class FritzahaQueryscriptSwitch implements FritzahaSwitchedOutlet {
    /**
     * Host ID
     */
    String host;
    /**
     * Device ID
     */
    String id;

    /**
     * {@inheritDoc}
     */
    public String getHost() {
        return host;
    }

    /**
     * {@inheritDoc}
     */
    public String getId() {
        return id;
    }

    /**
     * {@inheritDoc}
     */
    static final Logger logger = LoggerFactory.getLogger(FritzahaQueryscriptSwitch.class);

    /**
     * {@inheritDoc}
     */
    public void setSwitchState(boolean onOff, String itemName, FritzahaWebInterface webIface) {
        logger.debug("Setting Switch with Device ID " + id + " to value " + (onOff ? "on" : "off"));
        String path = "net/home_auto_query.lua";
        String args = "xhr=1&command=SwitchOnOff&value_to_set=" + (onOff ? 1 : 0) + "&id=" + id;
        webIface.asyncPost(path, args, new FritzahaQueryscriptUpdateSwitchCallback(path, args, webIface,
                FritzahaReauthCallback.Method.GET, 1, itemName));
    }

    /**
     * {@inheritDoc}
     */
    public void updateSwitchState(String itemName, FritzahaWebInterface webIface) {
        logger.debug("Getting Switch value for Device ID " + id);
        String path = "net/home_auto_query.lua";
        String args = "xhr=1&command=OutletStates&id=" + id;
        webIface.asyncGet(path, args, new FritzahaQueryscriptUpdateSwitchCallback(path, args, webIface,
                FritzahaReauthCallback.Method.GET, 1, itemName));
    }

    public FritzahaQueryscriptSwitch(String host, String id) {
        this.host = host;
        this.id = id;
    }
}
