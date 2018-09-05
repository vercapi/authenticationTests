/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package be.vercapi.oauth2provider;

import java.net.URI;
import java.util.logging.Logger;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import org.glassfish.jersey.client.ClientConfig;

import org.json.JSONObject;

/**
 *
 * @author vercapi
 */
public class OAuthValidation {
    
    public static final String STATUS_APPROVED = "true";
    public static final String ACTIVE_FIELD = "active";
    public static final String USERNAME_FIELD = "username";
    
    private static final Logger LOG = Logger.getLogger(OAuthValidation.class.getName());
    
    public String fBody;

    private final Response fResponse;

    private OAuthValidation(Response pResponse) {
        fResponse = pResponse;
    }

    public static OAuthValidation initOAuthValidation(String pToken, String pClientId, String pClientSecret, String pURL) {
        Response vResponse = activate(pToken, pClientId, pClientSecret, pURL);
        OAuthValidation vOAutHelper = new OAuthValidation(vResponse);

        return vOAutHelper;
    }
    
    public boolean isValid(){
        final int vStatusCode = fResponse.getStatus();
        boolean vResponseStatus = Response.Status.OK.getStatusCode() == vStatusCode;
        
        JSONObject vJson = getJSONBody();
        
        LOG.finest(vJson.toString());
        
        boolean vIsApproved = (Boolean) vJson.get(ACTIVE_FIELD);
        
        return vIsApproved && vResponseStatus;
    }
    
    public String getUsername(){
        String vRawString = (String) getJSONBody().get(USERNAME_FIELD);
        return vRawString.replace("/Common/ap_oauth_dev.", "");
    }
    
    public JSONObject getJSONBody(){
        if(fBody == null){
            fBody = fResponse.readEntity(String.class);
        }
        LOG.finest("Response: "+fBody);
        return new JSONObject(fBody);
    }

    private static Response activate(String pToken, String pClientSecret, String pClientId, String pURL) {
        ClientConfig config = new ClientConfig();
        Client client = ClientBuilder.newClient(config);

        URI vBaseURI = UriBuilder.fromUri(pURL).build();
        WebTarget target = client.target(vBaseURI);
        
        MultivaluedMap<String, String> vFormData = new MultivaluedHashMap<>();
        vFormData.add("token", pToken);
        vFormData.add("client_id", pClientId);
        vFormData.add("client_secret", pClientSecret);

        Response vResponse = target.path("introspect")
                .request()
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("variablePrefix", "!")
                .header("variableSuffix", "#")
                .post(Entity.form(vFormData), Response.class);
        
                /*header(HttpHeaders.AUTHORIZATION, "Bearer " + pToken).
                header("X-CEPA-CI", "CI af199fcde8b1ae909e7e3ec9de710023e970e9c1c09e605a").
                header("X-CEPA-CS", "CS 48611064d594186ae3b083b8ebb70023e970e9c1c09e605a").
                header("X-CEPA-ID", "ID XBHsRD7lCdME9rzyYb3AtLF0JL8AFfTs").
                header("Cache-Control", "no-cache"). 
                header("Postman-Token", "700c5636-f19e-47b1-93bb-7b318e1b253a").
                accept(MediaType.APPLICATION_JSON_TYPE).
                get(Response.class);*/

        return vResponse;
    }
}
