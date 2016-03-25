/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.io.caldav.internal.job;

import org.openhab.io.caldav.CalDavEvent;
import org.openhab.io.caldav.EventNotifier;
import org.openhab.io.caldav.internal.CalDavLoaderImpl;
import org.openhab.io.caldav.internal.EventStorage;
import org.openhab.io.caldav.internal.EventStorage.CalendarRuntime;
import org.openhab.io.caldav.internal.EventStorage.EventContainer;
import org.quartz.Job;
import org.quartz.JobExecutionContext;
import org.quartz.JobExecutionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EventJob implements Job {
    private static final Logger log = LoggerFactory.getLogger(EventJob.class);

    public static final String KEY_CONFIG = "config";
    public static final String KEY_EVENT = "event";
    public static final String KEY_REC_INDEX = "rec-index";
    public static final String KEY_EVENT_TRIGGER = "event-trigger";

    @Override
    public void execute(JobExecutionContext context) throws JobExecutionException {
        try {
            final String config = context.getJobDetail().getJobDataMap().getString(KEY_CONFIG);
            final String eventId = context.getJobDetail().getJobDataMap().getString(KEY_EVENT);
            final int recIndex = context.getJobDetail().getJobDataMap().getInt(KEY_REC_INDEX);
            final EventTrigger eventTrigger = EventTrigger
                    .valueOf(context.getJobDetail().getJobDataMap().getString(KEY_EVENT_TRIGGER));

            CalendarRuntime calendarRuntime = EventStorage.getInstance().getEventCache().get(config);
            if (calendarRuntime == null) {
                throw new JobExecutionException("cannot get runtime for config: " + config, false);
            }
            EventContainer eventContainer = calendarRuntime.getEventMap().get(eventId);
            if (eventContainer == null) {
                throw new JobExecutionException(
                        "cannot get event-container for config: " + config + " and eventId: " + eventId, false);
            }
            if (eventContainer.getEventList().size() <= recIndex) {
                throw new JobExecutionException("cannot get recurence-event for config: " + config + " and eventId: "
                        + eventId + " and occurence: " + recIndex, false);
            }
            CalDavEvent event = eventContainer.getEventList().get(recIndex);

            log.info("event {} for: {}", eventTrigger, event.getShortName());
            for (EventNotifier notifier : CalDavLoaderImpl.instance.getEventListenerList()) {
                try {
                    if (eventTrigger == EventTrigger.BEGIN) {
                        notifier.eventBegins(event);
                    } else if (eventTrigger == EventTrigger.END) {
                        notifier.eventEnds(event);
                    } else {
                        throw new IllegalStateException("not implemented event trigger: " + eventTrigger);
                    }
                } catch (Exception e) {
                    log.error("error while invoking listener", e);
                }
            }

            if (eventTrigger == EventTrigger.END) {
                // if event is ended, remove it from the map
                calendarRuntime.getEventMap().remove(eventContainer.getEventId());
            }
        } catch (Exception e) {
            log.error("error executing event job", e);
            throw new JobExecutionException("error executing event job", e, false);
        }
    }

    public static enum EventTrigger {
        BEGIN,
        END
    }
}
