/**
 * Copyright (c) 2010-2016, openHAB.org and others.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package org.openhab.core.transform.internal.service;

import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.util.Properties;
import org.apache.commons.io.IOUtils;
import org.openhab.core.transform.TransformationException;
import org.openhab.core.transform.TransformationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>
 * The implementation of {@link TransformationService} which simply maps strings to other strings
 * </p>
 * 
 * @author Kai Kreuzer
 * @author Gaël L'hopital
 * @since 0.8.0
 */
public class MapTransformationService extends LocalizableTransformationService implements TransformationService {

	static final Logger logger = LoggerFactory.getLogger(MapTransformationService.class);

	/**
	 * <p>
	 * Transforms the input <code>source</code> by mapping it to another string. It expects the mappings to be read from a file which
	 * is stored under the 'configurations/transform' folder. This file should be in property syntax, i.e. simple lines with "key=value" pairs.
	 * To organize the various transformations one might use subfolders.
	 * </p>
	 * 
	 * @param filename
	 *            the name of the file which contains the key value pairs for the mapping. The name may contain subfoldernames
	 *            as well
	 * @param source
	 *            the input to transform
	 * 
	 * @{inheritDoc}
	 * 
	 */
	public String transform(String filename, String source) throws TransformationException {

		if (filename == null || source == null) {
			throw new TransformationException("the given parameters 'filename' and 'source' must not be null");
		}
		
		String path = getLocalizedProposedFilename(filename);					
		Reader reader = null;
		try {						
			Properties properties = new Properties();
			reader = new FileReader(path);
			properties.load(reader);
			String target = properties.getProperty(source);
			if (target!=null) {
				logger.debug("transformation resulted in '{}'", target);
				return target;
			} else {
				logger.warn("Could not find a mapping for '{}' in the file '{}'.", source, filename);
				return "";
			}
		} catch (IOException e) {
			String message = "opening file '" + filename + "' throws exception";
			logger.error(message, e);
			throw new TransformationException(message, e);
		} finally {
			IOUtils.closeQuietly(reader);
		}
	}

}
