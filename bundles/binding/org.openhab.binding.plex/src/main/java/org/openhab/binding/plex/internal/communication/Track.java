/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.binding.plex.internal.communication;

import javax.xml.bind.annotation.XmlRootElement;

/**
 * Part of {@link MediaContainer}, holds information about a music track.
 *
 * @author Jeroen Idserda
 * @since 1.7.0
 */
@XmlRootElement(name = "Track")
public class Track extends AbstractSessionItem {

}
