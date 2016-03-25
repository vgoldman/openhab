/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.gpio.internal;

import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Extension of the default OSGi bundle activator.
 *
 * @author Dancho Penev
 * @since 1.5.0
 */
public class GPIOBindingActivator implements BundleActivator {

    private static Logger logger = LoggerFactory.getLogger(GPIOBindingActivator.class);

    /**
     * Called whenever the OSGi framework starts our bundle.
     */
    public void start(BundleContext context) throws Exception {
        logger.debug("GPIO binding has been started.");
    }

    /**
     * Called whenever the OSGi framework stops our bundle.
     */
    public void stop(BundleContext context) throws Exception {
        logger.debug("GPIO binding has been stopped.");
    }

}
