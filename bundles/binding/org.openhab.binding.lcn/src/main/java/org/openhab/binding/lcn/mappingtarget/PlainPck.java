/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.lcn.mappingtarget;

import org.openhab.binding.lcn.common.LcnAddr;
import org.openhab.binding.lcn.connection.Connection;
import org.openhab.binding.lcn.input.ModStatusBinSensors;
import org.openhab.binding.lcn.input.ModStatusKeyLocks;
import org.openhab.binding.lcn.input.ModStatusLedsAndLogicOps;
import org.openhab.binding.lcn.input.ModStatusOutput;
import org.openhab.binding.lcn.input.ModStatusRelays;
import org.openhab.binding.lcn.input.ModStatusVar;
import org.openhab.core.events.EventPublisher;
import org.openhab.core.items.Item;
import org.openhab.core.types.Command;

/**
 * Sends a plain LCN-PCK command.
 * Useful for special commands that are not directly supported.
 *
 * @author Tobias J�ttner
 */
public class PlainPck extends TargetWithLcnAddr {

    /** The plain PCK command without address header. */
    private final String pck;

    /**
     * Constructor.
     * 
     * @param addr the target LCN address
     * @param pck the plain PCK command without address header
     */
    PlainPck(LcnAddr addr, String pck) {
        super(addr);
        this.pck = pck;
    }

    /**
     * Tries to parse the given input text.
     * 
     * @param input the text to parse
     * @return the parsed {@link PlainPck} or null
     */
    static Target tryParseTarget(String input) {
        CmdAndAddressRet header = CmdAndAddressRet.parse(input, true);
        if (header != null) {
            switch (header.getCmd().toUpperCase()) {
                case "PCK":
                    return new PlainPck(header.getAddr(), header.getRestInput());
            }
        }
        return null;
    }

    /** {@inheritDoc} */
    @Override
    public void send(Connection conn, Item item, Command cmd) {
        conn.queue(this.addr, true, this.pck);
    }

    /** {@inheritDoc} */
    @Override
    public void register(Connection conn) {
    }

    /** {@inheritDoc} */
    @Override
    public boolean visualizationHandleOutputStatus(ModStatusOutput pchkInput, Command cmd, Item item,
            EventPublisher eventPublisher) {
        return false;
    }

    /** {@inheritDoc} */
    @Override
    public boolean visualizationHandleRelaysStatus(ModStatusRelays pchkInput, Command cmd, Item item,
            EventPublisher eventPublisher) {
        return false;
    }

    /** {@inheritDoc} */
    @Override
    public boolean visualizationBinSensorsStatus(ModStatusBinSensors pchkInput, Command cmd, Item item,
            EventPublisher eventPublisher) {
        return false;
    }

    /** {@inheritDoc} */
    @Override
    public boolean visualizationVarStatus(ModStatusVar pchkInput, Command cmd, Item item,
            EventPublisher eventPublisher) {
        return false;
    }

    /** {@inheritDoc} */
    @Override
    public boolean visualizationLedsAndLogicOpsStatus(ModStatusLedsAndLogicOps pchkInput, Command cmd, Item item,
            EventPublisher eventPublisher) {
        return false;
    }

    /** {@inheritDoc} */
    @Override
    public boolean visualizationKeyLocksStatus(ModStatusKeyLocks pchkInput, Command cmd, Item item,
            EventPublisher eventPublisher) {
        return false;
    }

}
