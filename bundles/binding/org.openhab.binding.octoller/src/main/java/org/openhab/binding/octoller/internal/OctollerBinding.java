/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.octoller.internal;

import java.util.Dictionary;

import org.apache.commons.lang.StringUtils;
import org.octoller.devicecom.Connection;
import org.openhab.binding.octoller.OctollerBindingProvider;
import org.openhab.core.binding.AbstractActiveBinding;
import org.openhab.core.types.Command;
import org.osgi.service.cm.ConfigurationException;
import org.osgi.service.cm.ManagedService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class sends commands and polls the states to / from the connected blocks
 * the octoller.
 *
 * @author JPlenert
 * @since 1.8.0
 */
public class OctollerBinding extends AbstractActiveBinding<OctollerBindingProvider>implements ManagedService {

    private static final Logger logger = LoggerFactory.getLogger(OctollerBinding.class);

    /**
     * the refresh interval which is used to poll values from the octoller
     * server (optional, defaults to 60000ms)
     */
    private long refreshInterval = 60000;

    public OctollerBinding() {
    }

    @Override
    public void activate() {
    }

    @Override
    public void deactivate() {
        // deallocate resources here that are no longer needed and
        // should be reset when activating this binding again
    }

    /**
     * @{inheritDoc
     */
    @Override
    protected long getRefreshInterval() {
        return refreshInterval;
    }

    /**
     * @{inheritDoc
     */
    @Override
    protected String getName() {
        return "octoller Refresh Service";
    }

    /**
     * @{inheritDoc
     */
    @Override
    protected void execute() {
        logger.debug("execute() method is called!");
        for (OctollerBindingProvider provider : providers) {
            for (String itemName : provider.getItemNames()) {
                OctollerBindingConfig config = provider.getConfig(itemName);
                if (config == null) {
                    continue;
                }

                try {
                    Connection con = new Connection(config.GatewayHost);
                    String result = con.doCommand(con.buildCommandString(config, "", ""));
                    con.processResultToPublisher(eventPublisher, itemName, result);
                    con.close();
                    logger.debug("OctollerBinding: Got state from " + itemName + " -> " + result);
                } catch (Exception e) {
                    e.printStackTrace();
                }

            }
        }

    }

    /**
     * @{inheritDoc
     */
    @Override
    protected void internalReceiveCommand(String itemName, Command command) {
        for (OctollerBindingProvider provider : providers) {
            OctollerBindingConfig config = provider.getConfig(itemName);
            if (config == null) {
                continue;
            }

            try {
                Connection con = new Connection(config.GatewayHost);
                String result = con.doCommand(
                        con.buildCommandString(config, command.getClass().getSimpleName(), command.toString()));
                con.processResultToPublisher(eventPublisher, itemName, result);
                con.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    protected void addBindingProvider(OctollerBindingProvider bindingProvider) {
        super.addBindingProvider(bindingProvider);
    }

    protected void removeBindingProvider(OctollerBindingProvider bindingProvider) {
        super.removeBindingProvider(bindingProvider);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void updated(Dictionary<String, ?> config) throws ConfigurationException {
        if (config != null) {
            String refreshIntervalString = (String) config.get("refresh");
            if (StringUtils.isNotBlank(refreshIntervalString)) {
                refreshInterval = Long.parseLong(refreshIntervalString);
            }

            setProperlyConfigured(true);
        }
    }

}
