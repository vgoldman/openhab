/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.rfxcom.internal.messages;

import java.util.Arrays;
import java.util.List;

import javax.xml.bind.DatatypeConverter;

import org.openhab.binding.rfxcom.RFXComValueSelector;
import org.openhab.binding.rfxcom.internal.RFXComException;
import org.openhab.core.library.items.ContactItem;
import org.openhab.core.library.items.NumberItem;
import org.openhab.core.library.items.StringItem;
import org.openhab.core.library.items.SwitchItem;
import org.openhab.core.library.types.DecimalType;
import org.openhab.core.library.types.OnOffType;
import org.openhab.core.library.types.OpenClosedType;
import org.openhab.core.library.types.StringType;
import org.openhab.core.types.State;
import org.openhab.core.types.Type;
import org.openhab.core.types.UnDefType;

/**
 * RFXCOM data class for lighting1 message. See X10, ARC, etc..
 *
 * @author Evert van Es, Cycling Engineer
 * @since 1.2.0
 */
public class RFXComLighting1Message extends RFXComBaseMessage {

    public enum SubType {
        X10(0),
        ARC(1),
        AB400D(2),
        WAVEMAN(3),
        EMW200(4),
        IMPULS(5),
        RISINGSUN(6),
        PHILIPS(7),
        ENERGENIE(8),

        UNKNOWN(255);

        private final int subType;

        SubType(int subType) {
            this.subType = subType;
        }

        SubType(byte subType) {
            this.subType = subType;
        }

        public byte toByte() {
            return (byte) subType;
        }
    }

    public enum Commands {
        OFF(0),
        ON(1),
        DIM(2),
        BRIGHT(3),
        GROUP_OFF(5),
        GROUP_ON(6),
        CHIME(7),

        UNKNOWN(255);

        private final int command;

        Commands(int command) {
            this.command = command;
        }

        Commands(byte command) {
            this.command = command;
        }

        public byte toByte() {
            return (byte) command;
        }
    }

    private final static List<RFXComValueSelector> supportedValueSelectors = Arrays.asList(RFXComValueSelector.RAW_DATA,
            RFXComValueSelector.SIGNAL_LEVEL, RFXComValueSelector.COMMAND, RFXComValueSelector.CONTACT);

    public SubType subType = SubType.X10;
    public char sensorId = 'A';
    public byte unitcode = 0;
    public Commands command = Commands.OFF;
    public byte signalLevel = 0;

    public RFXComLighting1Message() {
        packetType = PacketType.LIGHTING1;
    }

    public RFXComLighting1Message(byte[] data) {

        encodeMessage(data);
    }

    @Override
    public String toString() {
        String str = "";

        str += super.toString();
        str += "\n - Sub type = " + subType;
        str += "\n - Id = " + sensorId;
        str += "\n - Unit code = " + unitcode;
        str += "\n - Command = " + command;
        str += "\n - Signal level = " + signalLevel;

        return str;
    }

    @Override
    public void encodeMessage(byte[] data) {

        super.encodeMessage(data);

        try {
            subType = SubType.values()[super.subType];
        } catch (Exception e) {
            subType = SubType.UNKNOWN;
        }

        sensorId = (char) data[4];

        try {
            command = Commands.values()[data[6]];
        } catch (Exception e) {
            command = Commands.UNKNOWN;
        }

        if ((command == Commands.GROUP_ON) || (command == Commands.GROUP_OFF)) {
            unitcode = 0;
        } else {
            unitcode = data[5];
        }

        signalLevel = (byte) ((data[7] & 0xF0) >> 4);
    }

    @Override
    public byte[] decodeMessage() {
        // Example data 07 10 01 00 42 01 01 70
        // 07 10 01 00 42 10 06 70

        byte[] data = new byte[8];

        data[0] = 0x07;
        data[1] = RFXComBaseMessage.PacketType.LIGHTING1.toByte();
        data[2] = subType.toByte();
        data[3] = seqNbr;
        data[4] = (byte) sensorId;
        data[5] = unitcode;
        data[6] = command.toByte();
        data[7] = (byte) ((signalLevel & 0x0F) << 4);

        return data;
    }

    @Override
    public String generateDeviceId() {
        return sensorId + "." + unitcode;
    }

    @Override
    public State convertToState(RFXComValueSelector valueSelector) throws RFXComException {

        org.openhab.core.types.State state = UnDefType.UNDEF;

        if (valueSelector.getItemClass() == NumberItem.class) {

            if (valueSelector == RFXComValueSelector.SIGNAL_LEVEL) {

                state = new DecimalType(signalLevel);

            } else {
                throw new RFXComException("Can't convert " + valueSelector + " to NumberItem");
            }

        } else if (valueSelector.getItemClass() == SwitchItem.class) {

            if (valueSelector == RFXComValueSelector.COMMAND) {

                switch (command) {
                    case OFF:
                    case GROUP_OFF:
                    case DIM:
                        state = OnOffType.OFF;
                        break;

                    case ON:
                    case GROUP_ON:
                    case BRIGHT:
                        state = OnOffType.ON;
                        break;

                    case CHIME:
                        state = OnOffType.ON;
                        break;

                    default:
                        throw new RFXComException("Can't convert " + command + " to SwitchItem");
                }

            } else {
                throw new RFXComException("Can't convert " + valueSelector + " to SwitchItem");
            }

        } else if (valueSelector.getItemClass() == ContactItem.class) {

            if (valueSelector == RFXComValueSelector.CONTACT) {

                switch (command) {
                    case OFF:
                    case GROUP_OFF:
                    case DIM:
                        state = OpenClosedType.CLOSED;
                        break;

                    case ON:
                    case GROUP_ON:
                    case BRIGHT:
                        state = OpenClosedType.OPEN;
                        break;

                    case CHIME:
                        state = OpenClosedType.OPEN;
                        break;

                    default:
                        throw new RFXComException("Can't convert " + command + " to ContactItem");
                }

            } else {
                throw new RFXComException("Can't convert " + valueSelector + " to ContactItem");
            }

        } else if (valueSelector.getItemClass() == StringItem.class) {

            if (valueSelector == RFXComValueSelector.RAW_DATA) {

                state = new StringType(DatatypeConverter.printHexBinary(rawMessage));

            } else {
                throw new RFXComException("Can't convert " + valueSelector + " to StringItem");
            }

        } else {

            throw new RFXComException("Can't convert " + valueSelector + " to " + valueSelector.getItemClass());

        }

        return state;
    }

    @Override
    public void convertFromState(RFXComValueSelector valueSelector, String id, Object subType, Type type,
            byte seqNumber) throws RFXComException {

        boolean group = false;
        this.subType = ((SubType) subType);
        seqNbr = seqNumber;
        String[] ids = id.split("\\.");
        sensorId = ids[0].charAt(0);

        // Get unitcode, 0 means group
        unitcode = Byte.parseByte(ids[1]);
        if (unitcode == 0) {
            unitcode = 1;
            group = true;
        }

        switch (valueSelector) {
            case COMMAND:
                if (type instanceof OnOffType) {
                    if (group) {
                        command = (type == OnOffType.ON ? Commands.GROUP_ON : Commands.GROUP_OFF);
                    } else {
                        command = (type == OnOffType.ON ? Commands.ON : Commands.OFF);
                    }
                } else {
                    throw new RFXComException("Can't convert " + type + " to Command");
                }
                break;

            default:
                throw new RFXComException("Can't convert " + type + " to " + valueSelector);
        }

    }

    @Override
    public Object convertSubType(String subType) throws RFXComException {

        for (SubType s : SubType.values()) {
            if (s.toString().equals(subType)) {
                return s;
            }
        }

        throw new RFXComException("Unknown sub type " + subType);
    }

    @Override
    public List<RFXComValueSelector> getSupportedValueSelectors() throws RFXComException {
        return supportedValueSelectors;
    }

}
