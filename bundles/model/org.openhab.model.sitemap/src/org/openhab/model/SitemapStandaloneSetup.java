/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.model;

/**
 * Initialization support for running Xtext languages 
 * without equinox extension registry
 */
public class SitemapStandaloneSetup extends SitemapStandaloneSetupGenerated{

	public static void doSetup() {
		new SitemapStandaloneSetup().createInjectorAndDoEMFRegistration();
	}
}

