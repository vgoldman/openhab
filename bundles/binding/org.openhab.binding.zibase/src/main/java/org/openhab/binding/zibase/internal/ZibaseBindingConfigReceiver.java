/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.zibase.internal;

import java.lang.annotation.Inherited;
import java.util.Arrays;

import org.openhab.core.library.types.OnOffType;
import org.openhab.core.types.Command;
import org.openhab.core.types.State;

import fr.zapi.ZbAction;
import fr.zapi.ZbProtocol;
import fr.zapi.Zibase;

/**
 * This class handle receiver items the Zibase can manage @see authorizedProtocols
 *
 * @author Julien Tiphaine
 * @since 1.7.0
 *
 */
public class ZibaseBindingConfigReceiver extends ZibaseBindingConfig {

    /**
     * position in config array where to find protocol
     */
    static final int POS_PROTO = 2;

    /**
     * Zibase supported protocols for command sending
     */
    static final String[] authorizedProtocols = { ZbProtocol.CHACON.toString(), ZbProtocol.DOMIA.toString(),
            ZbProtocol.RFS10.toString(), ZbProtocol.VISONIC433.toString(), ZbProtocol.VISONIC868.toString(),
            ZbProtocol.X10.toString(), ZbProtocol.X2D433.toString(), ZbProtocol.X2D433ALRM.toString(),
            ZbProtocol.X2D868.toString(), ZbProtocol.X2D868ALRM.toString(), ZbProtocol.X2D868BOAC.toString(),
            ZbProtocol.X2D868INSH.toString(), ZbProtocol.X2D868PIWI.toString(), ZbProtocol.ZWAVE.toString(), };

    /**
     * Constructor
     * 
     * @param configParameters
     */
    public ZibaseBindingConfigReceiver(String[] configParameters) {
        super(configParameters);
    }

    /**
     * {@link Inherited}
     */
    @Override
    public void sendCommand(Zibase zibase, Command command, int dim) {

        ZbAction action = ZbAction.valueOf(command.toString());
        ZbProtocol protocol = ZbProtocol.valueOf(this.getProtocol());

        if (dim >= 0) {
            zibase.sendCommand(this.getId(), action, protocol, dim, 1);
        } else {
            zibase.sendCommand(this.getId(), action, protocol);
        }

        logger.debug("Send command to " + this.getId() + " : " + action.toString() + " / " + protocol.toString());
    }

    /**
     * get item protocol
     * 
     * @return
     */
    public String getProtocol() {
        return this.values[ZibaseBindingConfigReceiver.POS_PROTO];
    }

    /**
     * {@link Inherited}
     */
    @Override
    protected boolean isItemConfigValid() {
        logger.info("Checking config for Command item " + this.getId());

        if (Arrays.binarySearch(ZibaseBindingConfigReceiver.authorizedProtocols, this.getProtocol()) < 0) {
            logger.error("Unsupported command protocol for item " + this.getId());
            return false;
        }

        logger.info("Config OK for Command item " + this.getId());
        return true;
    }

    /**
     * {@link Inherited}
     */
    @Override
    public State getOpenhabStateFromZibaseValue(Zibase zibase, String zbResponseStr) {
        return OnOffType.valueOf(zibase.getState(this.getId()) ? "ON" : "OFF");
    }

}
