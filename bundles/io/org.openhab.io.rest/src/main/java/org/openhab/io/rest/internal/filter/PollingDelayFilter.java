/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.io.rest.internal.filter;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import javax.servlet.http.HttpServletRequest;

import org.atmosphere.cpr.AtmosphereResource;
import org.atmosphere.cpr.BroadcastFilter.BroadcastAction.ACTION;
import org.atmosphere.cpr.BroadcasterFactory;
import org.atmosphere.cpr.PerRequestBroadcastFilter;
import org.openhab.core.items.GroupItem;
import org.openhab.core.items.Item;
import org.openhab.io.rest.internal.broadcaster.GeneralBroadcaster;
import org.openhab.io.rest.internal.resources.ResponseTypeHelper;
import org.openhab.io.rest.internal.resources.beans.PageBean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This Filter delays the broadcast to polling connections. 
 * The delay is necessary for the completion of group events.
 *  
 * @author Oliver Mazur
 * @since 1.0
 */
public class PollingDelayFilter implements PerRequestBroadcastFilter {
	private static final Logger logger = LoggerFactory.getLogger(PollingDelayFilter.class);
	
	ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();
	
	@Override
	public BroadcastAction filter(String broadcasterId, Object originalMessage, Object message) {
		return new BroadcastAction(message);
	}

	@Override
	public BroadcastAction filter(String broadcasterId, final AtmosphereResource resource, Object originalMessage, final Object message) {
		final  HttpServletRequest request = resource.getRequest();
		try {	
			// delay first broadcast for long-polling and other polling transports
			boolean isItemMessage = originalMessage instanceof Item || originalMessage instanceof GroupItem;
			boolean isStreamingTransport = ResponseTypeHelper.isStreamingTransport(request);
			
			//strange atmosphere bug, seems harmless, but pollutes the logs
			//so lets see if this fails or not first before we call it again.
			try {
				resource.getRequest().getPathInfo();
			} catch (Exception e) {
				return new BroadcastAction(ACTION.ABORT, message);
			}
			if(!isStreamingTransport && message instanceof PageBean && isItemMessage) {
				final String delayedBroadcasterName = resource.getRequest().getPathInfo();
				executor.schedule(new Runnable() {
		            public void run() {
		                try {
		                    BroadcasterFactory broadcasterFactory = resource.getAtmosphereConfig().getBroadcasterFactory();
							GeneralBroadcaster delayedBroadcaster = broadcasterFactory.lookup(GeneralBroadcaster.class, delayedBroadcasterName);
							if(delayedBroadcaster != null)
								delayedBroadcaster.broadcast(message, resource);
						} catch (Exception e) {
							logger.error("Could not broadcast message", e);
						} 
		            }
		        }, 300, TimeUnit.MILLISECONDS);
			} else {
				//pass message to next filter
				return new BroadcastAction(ACTION.CONTINUE, message);
			}
			
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
		} 
		return new BroadcastAction(ACTION.ABORT, message);
	}
	
}