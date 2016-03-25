/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.urtsi.internal;

import org.openhab.core.binding.BindingConfig;

/**
 * This class contains all the configuration parameters you can define for the binding.
 *
 * @author Oliver Libutzki
 * @author John Cocula -- translated to Java
 * @since 1.3.0
 *
 */
class UrtsiItemConfiguration implements BindingConfig {

    /**
     * Serial port of the urtsi device
     */
    private final String deviceId;

    /**
     * Channel of the urtsi device
     */
    private final int channel;

    /**
     * Address of the urtsi device
     */
    private final int address;

    public UrtsiItemConfiguration(String deviceId, int channel, int address) {
        this.deviceId = deviceId;
        this.channel = channel;
        this.address = address;
    }

    public String getDeviceId() {
        return this.deviceId;
    }

    public int getChannel() {
        return this.channel;
    }

    public int getAddress() {
        return this.address;
    }

    @Override
    public int hashCode() {
        return (deviceId == null ? 0 : deviceId.hashCode()) + channel + address;
    }

    @Override
    public boolean equals(Object obj) {
        return (obj != null) && (obj instanceof UrtsiItemConfiguration)
                && deviceId.equals(((UrtsiItemConfiguration) obj).deviceId)
                && channel == ((UrtsiItemConfiguration) obj).channel
                && address == ((UrtsiItemConfiguration) obj).address;
    }

    @Override
    public String toString() {
        return "deviceId=" + (deviceId == null ? "" : deviceId) + ", channel=" + channel + "address=" + address;
    }
}
