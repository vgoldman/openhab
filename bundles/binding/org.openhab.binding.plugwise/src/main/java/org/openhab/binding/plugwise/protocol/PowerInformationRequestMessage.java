/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.plugwise.protocol;

/**
 * Message to request real-time energy consumption
 *
 * @author Karel Goderis
 * @since 1.1.0
 */
public class PowerInformationRequestMessage extends Message {

    public PowerInformationRequestMessage(String MAC) {
        super(MAC, "");
        type = MessageType.POWER_INFORMATION_REQUEST;
    }

    @Override
    protected String payLoadToHexString() {
        return "";
    }

    @Override
    protected void parsePayLoad() {
    }

    @Override
    protected String sequenceNumberToHexString() {
        return "";
    }

}
