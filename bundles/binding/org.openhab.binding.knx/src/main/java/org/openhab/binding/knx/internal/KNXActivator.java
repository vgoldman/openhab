/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.knx.internal;

import org.openhab.binding.knx.internal.logging.LogAdapter;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import tuwien.auto.calimero.log.LogManager;

/**
 * Extension of the default OSGi bundle activator
 */
public final class KNXActivator implements BundleActivator {

    private static Logger logger = LoggerFactory.getLogger(KNXActivator.class);
    private final LogAdapter logAdapter = new LogAdapter();

    /**
     * Called whenever the OSGi framework starts our bundle
     */
    @Override
    public void start(BundleContext bc) throws Exception {
        logger.debug("KNX binding has been started.");
        // Set global (null) logger for calimero.
        LogManager.getManager().addWriter(null, logAdapter);
    }

    /**
     * Called whenever the OSGi framework stops our bundle
     */
    @Override
    public void stop(BundleContext bc) throws Exception {
        // Remove global (null) logger for calimero.
        LogManager.getManager().removeWriter(null, logAdapter);
        logger.debug("KNX binding has been stopped.");
    }
}
