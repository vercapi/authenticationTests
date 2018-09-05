/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package be.vercapi.OAuthEndpoint;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author vercapi
 */
public enum OAuthProperties {
    CLIENT_SECRET,
    CLIENT_ID,
    AUTHORIZATION_URI,
    REDIRECTION_URI,
    TOKEN_URI;

    public String getValue() {
        try {
            return getProperties().getProperty(name());
        } catch (IOException ex) {
            LOG.log(Level.SEVERE, "value for "+toString()+" niet gevonden", ex);
            return "ERROR";
        }
    }
    
    private static final String PROPERTY_FILE = "/be/vercapi/OAuthEndpoint/oauth.properties";
    private static Properties fProperties = null;
    private static final Logger LOG =  Logger.getLogger(OAuthProperties.class.getName());

    public static Properties getProperties() throws IOException {
            InputStream vInputStream;
            vInputStream = OAuthProperties.class.getClassLoader().getResourceAsStream(PROPERTY_FILE);
            
            if(vInputStream == null){
                throw new IOException("Could not find file on classpath: "+PROPERTY_FILE);
            }

            if (fProperties == null) {
                fProperties = new Properties();
                fProperties.load(vInputStream);
            }

            return fProperties;
    }

}
