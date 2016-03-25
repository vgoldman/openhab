/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.primare.internal.protocol.spa20;

import org.openhab.binding.primare.internal.protocol.PrimareTCPConnector;

/**
 * Connector for Primare SP31/SP31.7/SPA20/SPA21 TCP communication.
 *
 * @author juslive
 * @since 1.7.0
 */
public class PrimareSPA20TCPConnector extends PrimareTCPConnector {

    /**
     * Create a {@link PrimareTCPConnector} capable of communicating
     * with a Primare SP31/SP31.7/SPA20/SPA21 device using TCP/IP
     *
     * @param deviceId
     *            device id as given in OpenHAB configuration
     * @param host
     *            host name or IP address
     * @param port
     *            port number
     *
     * @return Primare TCP connector instance
     */
    public PrimareSPA20TCPConnector(String deviceId, String host, int port) {
        super(deviceId, host, port, new PrimareSPA20MessageFactory(), new PrimareSPA20ResponseFactory());
    }
}
