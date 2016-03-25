/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.dscalarm;

public interface DSCAlarmActionProvider {

    /**
     * Sends a DSC Alarm command
     * 
     * @param command
     * @param data TODO
     * 
     * @return
     */
    public boolean sendDSCAlarmCommand(String command, String data);

}
