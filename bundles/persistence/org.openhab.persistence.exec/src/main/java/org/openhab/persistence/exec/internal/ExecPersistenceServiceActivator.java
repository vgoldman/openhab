/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.persistence.exec.internal;

import org.openhab.core.persistence.PersistenceService;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This is the implementation of the Exec {@link PersistenceService}.
 *
 * @author Henrik Sjöstrand
 * @since 1.1.0
 */
public class ExecPersistenceServiceActivator implements BundleActivator {

    private static final Logger logger = LoggerFactory.getLogger(ExecPersistenceServiceActivator.class);

    /**
     * Called whenever the OSGi framework starts our bundle
     */
    @Override
    public void start(BundleContext bc) throws Exception {
        logger.debug("Exec persistence bundle has been started.");
    }

    /**
     * Called whenever the OSGi framework stops our bundle
     */
    @Override
    public void stop(BundleContext bc) throws Exception {
        logger.debug("Exec persistence bundle stopping.");
    }

}
