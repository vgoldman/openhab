/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.gc100ir.internal;

import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Extension of the default OSGi bundle activator
 * 
 * @author Parikshit Thakur & Team
 * @since 1.9.0
 */
public final class GC100IRActivator implements BundleActivator {

    private static Logger logger = LoggerFactory.getLogger(GC100IRActivator.class);

    private static BundleContext context;

    /**
     * Called whenever the OSGi framework starts our bundle
     */
    public void start(BundleContext bc) throws Exception {
        context = bc;
        logger.debug("GC100IR binding has been started");
    }

    /**
     * Called whenever the OSGi framework stops our bundle
     */
    public void stop(BundleContext bc) throws Exception {
        context = null;
        logger.debug("GC100IR binding has been stopped");
    }

    /**
     * Returns the bundle context of this bundle
     * 
     * @return the bundle context
     */
    public static BundleContext getContext() {
        return context;
    }

}
