/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.zwave.internal.protocol.commandclass;

import java.util.ArrayList;
import java.util.Collection;

import org.openhab.binding.zwave.internal.config.ZWaveDbCommandClass;
import org.openhab.binding.zwave.internal.protocol.SerialMessage;
import org.openhab.binding.zwave.internal.protocol.SerialMessage.SerialMessageClass;
import org.openhab.binding.zwave.internal.protocol.SerialMessage.SerialMessagePriority;
import org.openhab.binding.zwave.internal.protocol.SerialMessage.SerialMessageType;
import org.openhab.binding.zwave.internal.protocol.ZWaveController;
import org.openhab.binding.zwave.internal.protocol.ZWaveEndpoint;
import org.openhab.binding.zwave.internal.protocol.ZWaveNode;
import org.openhab.binding.zwave.internal.protocol.event.ZWaveCommandClassValueEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.thoughtworks.xstream.annotations.XStreamAlias;
import com.thoughtworks.xstream.annotations.XStreamOmitField;

/**
 * Handles the Multi Level Switch command class. Multi level switches accept
 * on / off
 * on or off and report their status as on (0xFF) or off (0x00).
 * The commands include the possibility to set a given level, get a given
 * level and report a level.
 * Z-Wave dimmers have a range from 0 (off) to 99 (on). 255 (0xFF) means restore
 * to previous level. We translate 99 to 100%, so it's impossible to set
 * the level to 99%.
 *
 * @author Jan-Willem Spuij
 * @since 1.3.0
 */
@XStreamAlias("multiLevelSwitchCommandClass")
public class ZWaveMultiLevelSwitchCommandClass extends ZWaveCommandClass
        implements ZWaveBasicCommands, ZWaveCommandClassDynamicState {

    @XStreamOmitField
    private static final Logger logger = LoggerFactory.getLogger(ZWaveMultiLevelSwitchCommandClass.class);
    private static final int MAX_SUPPORTED_VERSION = 3;

    private static final int SWITCH_MULTILEVEL_SET = 0x01;
    private static final int SWITCH_MULTILEVEL_GET = 0x02;
    private static final int SWITCH_MULTILEVEL_REPORT = 0x03;
    private static final int SWITCH_MULTILEVEL_START_LEVEL_CHANGE = 0x04;
    private static final int SWITCH_MULTILEVEL_STOP_LEVEL_CHANGE = 0x05;
    private static final int SWITCH_MULTILEVEL_SUPPORTED_GET = 0x06;
    private static final int SWITCH_MULTILEVEL_SUPPORTED_REPORT = 0x07;

    @XStreamOmitField
    private boolean dynamicDone = false;

    private boolean isGetSupported = true;

    /**
     * Creates a new instance of the ZWaveMultiLevelSwitchCommandClass class.
     *
     * @param node the node this command class belongs to
     * @param controller the controller to use
     * @param endpoint the endpoint this Command class belongs to
     */
    public ZWaveMultiLevelSwitchCommandClass(ZWaveNode node, ZWaveController controller, ZWaveEndpoint endpoint) {
        super(node, controller, endpoint);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public CommandClass getCommandClass() {
        return CommandClass.SWITCH_MULTILEVEL;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getMaxVersion() {
        return MAX_SUPPORTED_VERSION;
    };

    /**
     * {@inheritDoc}
     */
    @Override
    public void handleApplicationCommandRequest(SerialMessage serialMessage, int offset, int endpoint) {
        logger.debug("NODE {}: Received Switch Multi Level Request", this.getNode().getNodeId());
        int command = serialMessage.getMessagePayloadByte(offset);
        switch (command) {
            case SWITCH_MULTILEVEL_SET:
            case SWITCH_MULTILEVEL_GET:
            case SWITCH_MULTILEVEL_SUPPORTED_GET:
            case SWITCH_MULTILEVEL_SUPPORTED_REPORT:
                logger.warn("Command {} not implemented.", command);
            case SWITCH_MULTILEVEL_START_LEVEL_CHANGE:
                return;
            case SWITCH_MULTILEVEL_STOP_LEVEL_CHANGE:
                logger.debug("NODE {}: Process Switch Multi Level Stop Level Change", this.getNode().getNodeId());
                // request level after dimming
                logger.debug("NODE {}: Requesting level from endpoint {}", this.getNode().getNodeId(), endpoint);
                this.getController().sendData(this.getNode().encapsulate(this.getValueMessage(), this, endpoint));
                break;
            case SWITCH_MULTILEVEL_REPORT:
                logger.trace("Process Switch Multi Level Report");

                int value = serialMessage.getMessagePayloadByte(offset + 1);
                logger.debug("NODE {}: Switch Multi Level report, value = {}", this.getNode().getNodeId(), value);
                ZWaveCommandClassValueEvent zEvent = new ZWaveCommandClassValueEvent(this.getNode().getNodeId(),
                        endpoint, this.getCommandClass(), value);
                this.getController().notifyEventListeners(zEvent);

                dynamicDone = true;
                break;
            default:
                logger.warn(String.format("Unsupported Command 0x%02X for command class %s (0x%02X).", command,
                        this.getCommandClass().getLabel(), this.getCommandClass().getKey()));
        }
    }

    /**
     * Gets a SerialMessage with the SWITCH_MULTILEVEL_GET command
     *
     * @return the serial message
     */
    @Override
    public SerialMessage getValueMessage() {
        if (isGetSupported == false) {
            logger.debug("NODE {}: Node doesn't support get requests", this.getNode().getNodeId());
            return null;
        }

        logger.debug("NODE {}: Creating new message for command SWITCH_MULTILEVEL_GET", this.getNode().getNodeId());
        SerialMessage result = new SerialMessage(this.getNode().getNodeId(), SerialMessageClass.SendData,
                SerialMessageType.Request, SerialMessageClass.ApplicationCommandHandler, SerialMessagePriority.Get);
        byte[] newPayload = { (byte) this.getNode().getNodeId(), 2, (byte) getCommandClass().getKey(),
                (byte) SWITCH_MULTILEVEL_GET };
        result.setMessagePayload(newPayload);
        return result;
    }

    @Override
    public boolean setOptions(ZWaveDbCommandClass options) {
        if (options.isGetSupported != null) {
            isGetSupported = options.isGetSupported;
        }

        return true;
    }

    /**
     * Gets a SerialMessage with the SWITCH_MULTILEVEL_SET command
     *
     * @param the level to set. 0 is mapped to off, > 0 is mapped to on.
     * @return the serial message
     */
    @Override
    public SerialMessage setValueMessage(int level) {
        logger.debug("NODE {}: Creating new message for command SWITCH_MULTILEVEL_SET", this.getNode().getNodeId());
        SerialMessage result = new SerialMessage(this.getNode().getNodeId(), SerialMessageClass.SendData,
                SerialMessageType.Request, SerialMessageClass.SendData, SerialMessagePriority.Set);
        byte[] newPayload = { (byte) this.getNode().getNodeId(), 3, (byte) getCommandClass().getKey(),
                (byte) SWITCH_MULTILEVEL_SET, (byte) level };
        result.setMessagePayload(newPayload);
        return result;
    }

    /**
     * Gets a SerialMessage with the SWITCH_MULTILEVEL_STOP_LEVEL_CHANGE command
     *
     * @return the serial message
     */
    public SerialMessage stopLevelChangeMessage() {
        logger.debug("NODE {}: Creating new message for command SWITCH_MULTILEVEL_STOP_LEVEL_CHANGE",
                this.getNode().getNodeId());
        SerialMessage result = new SerialMessage(this.getNode().getNodeId(), SerialMessageClass.SendData,
                SerialMessageType.Request, SerialMessageClass.SendData, SerialMessagePriority.Set);
        byte[] newPayload = { (byte) this.getNode().getNodeId(), 2, (byte) getCommandClass().getKey(),
                (byte) SWITCH_MULTILEVEL_STOP_LEVEL_CHANGE };
        result.setMessagePayload(newPayload);
        return result;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Collection<SerialMessage> getDynamicValues(boolean refresh) {
        ArrayList<SerialMessage> result = new ArrayList<SerialMessage>();
        if (refresh == true || dynamicDone == false) {
            result.add(getValueMessage());
        }
        return result;
    }
}
