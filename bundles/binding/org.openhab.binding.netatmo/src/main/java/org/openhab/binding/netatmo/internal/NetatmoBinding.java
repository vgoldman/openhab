/**
 * Copyright (c) 2010-2015, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.netatmo.internal;

import static org.apache.commons.lang.StringUtils.isNotBlank;
import static org.openhab.binding.netatmo.internal.NetatmoGenericBindingProvider.*;

import java.util.Dictionary;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import org.openhab.binding.netatmo.NetatmoBindingProvider;
import org.openhab.binding.netatmo.internal.authentication.OAuthCredentials;
import org.openhab.binding.netatmo.internal.camera.NetatmoCameraBinding;
import org.openhab.binding.netatmo.internal.weather.NetatmoPressureUnit;
import org.openhab.binding.netatmo.internal.weather.NetatmoUnitSystem;
import org.openhab.binding.netatmo.internal.weather.NetatmoWeatherBinding;
import org.openhab.core.binding.AbstractActiveBinding;
import org.osgi.service.cm.ConfigurationException;
import org.osgi.service.cm.ManagedService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Binding that gets measurements from the Netatmo API every couple of minutes.
 *
 * @author Andreas Brenk
 * @author Thomas.Eichstaedt-Engelen
 * @author Gaël L'hopital
 * @author Rob Nielsen
 * @author Ing. Peter Weiss
 * @since 1.4.0
 */
public class NetatmoBinding extends AbstractActiveBinding<NetatmoBindingProvider>implements ManagedService {

    private static final String DEFAULT_USER_ID = "DEFAULT_USER";

    private static final Logger logger = LoggerFactory.getLogger(NetatmoBinding.class);

    protected static final String CONFIG_CLIENT_ID = "clientid";
    protected static final String CONFIG_CLIENT_SECRET = "clientsecret";
    protected static final String CONFIG_REFRESH = "refresh";
    protected static final String CONFIG_REFRESH_TOKEN = "refreshtoken";
    protected static final String CONFIG_PRESSURE_UNIT = "pressureunit";
    protected static final String CONFIG_UNIT_SYSTEM = "unitsystem";

    /**
     * The refresh interval which is used to poll values from the Netatmo server
     * (optional, defaults to 300000ms)
     */
    private long refreshInterval = 300000;

    private static Map<String, OAuthCredentials> credentialsCache = new HashMap<String, OAuthCredentials>();

    private final NetatmoCameraBinding cameraBinding = new NetatmoCameraBinding();
    private final NetatmoWeatherBinding weatherBinding = new NetatmoWeatherBinding();

    /**
     * {@inheritDoc}
     */
    @Override
    protected String getName() {
        return "Netatmo Refresh Service";
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected long getRefreshInterval() {
        return this.refreshInterval;
    }

    /**
     * /**
     * {@inheritDoc}
     */
    @SuppressWarnings("incomplete-switch")
    @Override
    protected void execute() {
        logger.debug("Querying Netatmo API");
        for (String userid : credentialsCache.keySet()) {

            // Check if weather and/or camera items are configured
            boolean bWeather = false;
            boolean bCamera = false;

            for (final NetatmoBindingProvider provider : providers) {
                for (final String itemName : provider.getItemNames()) {
                    final String sItemType = provider.getItemType(itemName);
                    if (NETATMO_WEATHER.equals(sItemType)) {
                        bWeather = true;
                    } else if (NETATMO_CAMERA.equals(sItemType)) {
                        bCamera = true;
                    }
                    if (bWeather && bCamera) {
                        break;
                    }
                }
            }

            OAuthCredentials oauthCredentials = getOAuthCredentials(userid);
            oauthCredentials.setWeather(bWeather);
            oauthCredentials.setCamera(bCamera);
            if (oauthCredentials.noAccessToken()) {
                // initial run after a restart, so get an access token first
                oauthCredentials.refreshAccessToken();
            }

            // Start the execution of the weather station and/or camera binding
            if (bWeather) {
                weatherBinding.execute(oauthCredentials, this.providers, this.eventPublisher);
            }
            if (bCamera) {
                cameraBinding.execute(oauthCredentials, this.providers, this.eventPublisher);
            }
        }
    }

    /**
     * Returns the cached {@link OAuthCredentials} for the given {@code userid}.
     * If their is no such cached {@link OAuthCredentials} element, the cache is
     * searched with the {@code DEFAULT_USER}. If there is still no cached
     * element found {@code NULL} is returned.
     *
     * @param userid
     *            the userid to find the {@link OAuthCredentials}
     * @return the cached {@link OAuthCredentials} or {@code NULL}
     */
    public static OAuthCredentials getOAuthCredentials(String userid) {
        if (credentialsCache.containsKey(userid)) {
            return credentialsCache.get(userid);
        } else {
            return credentialsCache.get(DEFAULT_USER_ID);
        }
    }

    protected void addBindingProvider(NetatmoBindingProvider bindingProvider) {
        super.addBindingProvider(bindingProvider);
    }

    protected void removeBindingProvider(NetatmoBindingProvider bindingProvider) {
        super.removeBindingProvider(bindingProvider);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void updated(final Dictionary<String, ?> config) throws ConfigurationException {
        if (config != null) {

            final String refreshIntervalString = (String) config.get(CONFIG_REFRESH);
            if (isNotBlank(refreshIntervalString)) {
                this.refreshInterval = Long.parseLong(refreshIntervalString);
            }

            Enumeration<String> configKeys = config.keys();
            while (configKeys.hasMoreElements()) {
                String configKey = configKeys.nextElement();

                // the config-key enumeration contains additional keys that we
                // don't want to process here ...
                if (CONFIG_REFRESH.equals(configKey) || "service.pid".equals(configKey)) {
                    continue;
                }

                String userid;
                String configKeyTail;

                if (configKey.contains(".")) {
                    String[] keyElements = configKey.split("\\.");
                    userid = keyElements[0];
                    configKeyTail = keyElements[1];

                } else {
                    userid = DEFAULT_USER_ID;
                    configKeyTail = configKey;
                }

                OAuthCredentials credentials = credentialsCache.get(userid);
                if (credentials == null) {
                    credentials = new OAuthCredentials();
                    credentialsCache.put(userid, credentials);
                }

                String value = (String) config.get(configKeyTail);

                if (CONFIG_CLIENT_ID.equals(configKeyTail)) {
                    credentials.setClientId(value);
                } else if (CONFIG_CLIENT_SECRET.equals(configKeyTail)) {
                    credentials.setClientSecret(value);
                } else if (CONFIG_REFRESH_TOKEN.equals(configKeyTail)) {
                    credentials.setRefreshToken(value);
                } else if (CONFIG_PRESSURE_UNIT.equals(configKeyTail)) {
                    try {
                        weatherBinding.setPressureUnit(NetatmoPressureUnit.fromString(value));
                    } catch (IllegalArgumentException e) {
                        throw new ConfigurationException(configKey,
                                "the value '" + value + "' is not valid for the configKey '" + configKey + "'");
                    }
                } else if (CONFIG_UNIT_SYSTEM.equals(configKeyTail)) {
                    try {
                        weatherBinding.setUnitSystem(NetatmoUnitSystem.fromString(value));
                    } catch (IllegalArgumentException e) {
                        throw new ConfigurationException(configKey,
                                "the value '" + value + "' is not valid for the configKey '" + configKey + "'");
                    }
                } else {
                    throw new ConfigurationException(configKey, "the given configKey '" + configKey + "' is unknown");
                }
            }

            setProperlyConfigured(true);
        }
    }

}
