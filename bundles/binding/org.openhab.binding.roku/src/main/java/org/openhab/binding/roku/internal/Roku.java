package org.openhab.binding.roku.internal;

import java.awt.Image;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;

import javax.imageio.ImageIO;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.openhab.io.net.actions.HTTP;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

public class Roku {
    static final Logger logger = LoggerFactory.getLogger(Roku.class);

    private static final String ROKU_CACHE_PATH = "webapps/images";
    private static final int ICON_WIDTH = 30;
    private String ROKU_PORT = "8060";
    private String rokuIP;
    private String rokuUSN;
    private String rokuURL;
    boolean interfaceRefreshRequired = true;

    HashMap<String, String> rokuAppsMap = new HashMap<String, String>();

    public Roku(String ipAddress, String uniqueSerialNumber, boolean isInterfaceRefreshRequired) throws Exception {
        rokuIP = ipAddress;
        rokuUSN = uniqueSerialNumber;
        rokuURL = "http://" + rokuIP + ":" + ROKU_PORT;
        this.interfaceRefreshRequired = isInterfaceRefreshRequired;
        queryApps();

    }

    public void queryApps() throws Exception {
        // URL url = new URL(rokuURL + "/query/apps");
        // HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        // connection.setRequestMethod("GET");
        String response = HTTP.sendHttpGetRequest(rokuURL + "/query/apps");
        // InputStream xml = connection.getInputStream();
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document xmlDocument = db.parse(new InputSource(new StringReader(response)));
        Node appNode = xmlDocument.getFirstChild();
        Node app = appNode.getFirstChild();

        while (app != null) {
            String nodeName = app.getNodeName();
            if (nodeName.equals("app")) {
                String appID = app.getAttributes().getNamedItem("id").getNodeValue();
                rokuAppsMap.put(appID, app.getTextContent());
                saveIcon(appID);
            }

            app = app.getNextSibling();
        }
        // connection.disconnect();
        return;
    }

    boolean validateCommand(String command) {
        for (RokuKeyCommand rokuCommand : RokuKeyCommand.class.getEnumConstants()) {
            if (rokuCommand.name().equals(command)) {
                return true;
            }
        }
        return false;
    }

    public void saveIcon(String appID) throws MalformedURLException, IOException {
        BufferedImage sourceImage = ImageIO.read(new URL(rokuURL + "/query/icon/" + appID));
        Image thumbnail = sourceImage.getScaledInstance(ICON_WIDTH, -1, Image.SCALE_SMOOTH);
        BufferedImage bufferedIcon = new BufferedImage(thumbnail.getWidth(null), thumbnail.getHeight(null),
                BufferedImage.TYPE_INT_RGB);
        bufferedIcon.getGraphics().drawImage(thumbnail, 0, 0, null);
        ImageIO.write(bufferedIcon, "png", new File(ROKU_CACHE_PATH + "/" + rokuUSN + "_" + appID + ".png"));

    }

    public enum RokuKeyCommand {
        Home,
        Rev,
        Fwd,
        Play,
        Select,
        Left,
        Right,
        Down,
        Up,
        Back,
        InstantReplay,
        Info,
        Backspace,
        Search,
        Enter,
        VolumeDown,
        VolumeMute,
        VolumeUp
    }

    public String getRokuUSN() {
        return rokuUSN;
    }
}
