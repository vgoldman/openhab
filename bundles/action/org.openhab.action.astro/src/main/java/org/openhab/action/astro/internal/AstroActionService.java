/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.action.astro.internal;

import org.openhab.core.scriptengine.action.ActionService;

/**
 * This class registers an OSGi service for the Astro action.
 *
 * @author Gerhard Riegler
 * @since 1.7.0
 */
public class AstroActionService implements ActionService {

    public void activate() {
    }

    public void deactivate() {
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getActionClassName() {
        return Astro.class.getCanonicalName();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Class<?> getActionClass() {
        return Astro.class;
    }

}
