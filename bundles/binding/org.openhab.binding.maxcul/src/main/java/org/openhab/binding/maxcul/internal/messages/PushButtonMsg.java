/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.maxcul.internal.messages;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Message from Push Button devices
 *
 * @author Paul Hampson (cyclingengineer)
 * @since 1.6.0
 */
public class PushButtonMsg extends BaseMsg {

    final static private int PUSH_BUTTON_PAYLOAD_LEN = 2; /* in bytes */

    public enum PushButtonMode {
        AUTO,
        ECO,
        UNKNOWN;
    }

    private PushButtonMode mode = PushButtonMode.UNKNOWN;
    private boolean isRetransmission = false;
    private boolean batteryLow;

    private boolean rfError;

    private static final Logger logger = LoggerFactory.getLogger(PushButtonMsg.class);

    public PushButtonMsg(String rawMsg) {
        super(rawMsg);
        logger.debug(this.msgType + " Payload Len -> " + this.payload.length);

        if (this.payload.length == PUSH_BUTTON_PAYLOAD_LEN) {
            if (this.payload[0] == 0x50) {
                // behaviour
                isRetransmission = true;
            }

            if (this.payload[1] == 0x0) {
                mode = PushButtonMode.ECO;
            } else if (this.payload[1] == 0x1) {
                mode = PushButtonMode.AUTO;
            }
        } else {
            logger.error("Got " + this.msgType + " message with incorrect length!");
        }
        rfError = extractBitFromByte(this.payload[0], 6);
        /* extract battery status */
        batteryLow = extractBitFromByte(this.payload[0], 7);
    }

    public PushButtonMode getMode() {
        return mode;
    }

    public boolean isRetransmission() {
        return isRetransmission;
    }

    public boolean getBatteryLow() {
        return batteryLow;
    }

    @Override
    protected void printFormattedPayload() {
        super.printFormattedPayload();
        logger.debug("\tMode 				=> " + mode);
        logger.debug("\tRF Error            => " + rfError);
        logger.debug("\tBattery Low         => " + batteryLow);
    }
}
