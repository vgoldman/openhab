package org.openhab.binding.roku.internal;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RokuInterfaceGenerator {
    static final Logger logger = LoggerFactory.getLogger(RokuInterfaceGenerator.class);

    private static String ITEMS_PATH = "configurations/items/";

    public static void generateInterface(Roku roku) throws IOException {

        String itemsFileName = ITEMS_PATH + roku.getRokuUSN() + ".items";

        File f = new File(itemsFileName);
        if (f.exists() && !f.isDirectory() && !roku.interfaceRefreshRequired) {
            logger.info("Items file exists for Roku " + roku.getRokuUSN()
                    + " and forceInterfaceRefresh is set to false, refresh will not be performed");
            return;

        }
        List<String> lines = new ArrayList<String>();// Arrays.asList("The first line", "The second line");
        Path file = Paths.get(itemsFileName);

        Iterator<Entry<String, String>> it = roku.rokuAppsMap.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, String> pair = it.next();

            // it.remove(); // avoids a ConcurrentModificationException
            String app_id = pair.getKey();
            String app_desc = pair.getValue();
            logger.debug("Adding Roku item for " + app_id + " = " + app_desc);
            String app_item_id = roku.getRokuUSN() + "_" + app_id;
            lines.add("Switch " + app_item_id + " \"" + app_desc + "\" " + "<" + app_item_id + ">" + "{roku:launch:"
                    + app_id + "}");
        }

        Files.write(file, lines, Charset.forName("UTF-8"));
    }
}
