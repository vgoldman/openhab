/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.ipx800.internal.exception;

/**
 * Device doesn't exist in configuration
 * 
 * @author Seebag
 * @since 1.8.0
 *
 */
public class Ipx800UnknownDeviceException extends Ipx800Exception {

    public Ipx800UnknownDeviceException(String message) {
        super(message);
    }

    /**
     * 
     */
    private static final long serialVersionUID = -4408071685549295251L;

}
