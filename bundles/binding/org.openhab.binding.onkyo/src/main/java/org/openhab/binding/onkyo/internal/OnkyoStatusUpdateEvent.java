/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.onkyo.internal;

import java.util.EventObject;

/**
 * The listener interface for receiving status updates from Onkyo receiver.
 *
 * @author Pauli Anttila
 * @since 1.3.0
 */
public class OnkyoStatusUpdateEvent extends EventObject {

    private static final long serialVersionUID = -2256210413245865703L;

    public OnkyoStatusUpdateEvent(Object source) {
        super(source);
    }

    /**
     * Invoked when received status updates from Onkyo receiver.
     * 
     * @param data
     *            Data from receiver.
     * 
     */
    public void StatusUpdateEventReceived(String ip, String data) {
    }

}
