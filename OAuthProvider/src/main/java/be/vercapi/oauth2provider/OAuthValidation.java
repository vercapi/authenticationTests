/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package be.vercapi.oauth2provider;

import java.net.URI;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.glassfish.jersey.client.ClientConfig;

import org.json.JSONObject;

/**
 *
 * @author vercapi
 */
public class OAuthValidation {
    
    public static final String STATUS_APPROVED = "approved";
    public static final String STATUS_FIELD = "status";
    public static final String USERNAME_FIELD = "context";

    private final Response fResponse;

    private OAuthValidation(Response pResponse) {
        fResponse = pResponse;
    }

    public static OAuthValidation initOAuthValidation(String pToken) {
        Response vResponse = activate(pToken);
        OAuthValidation vOAutHelper = new OAuthValidation(vResponse);

        return vOAutHelper;
    }
    
    public boolean isValid(){
        final int vStatusCode = fResponse.getStatus();
        boolean vResponseStatus = Response.Status.OK.getStatusCode() == vStatusCode;
        
        String vStatusToken = (String) getJSONBody().get(STATUS_FIELD);
        boolean vIsApproved = STATUS_APPROVED.equals(vStatusToken);
        
        return vIsApproved && vResponseStatus;
    }
    
    public String getUsername(){
        return (String) getJSONBody().get(USERNAME_FIELD);
    }
    
    public JSONObject getJSONBody(){
        String vBody = fResponse.readEntity(String.class);
        return new JSONObject(vBody);
    }

    private static Response activate(String pToken) {
        ClientConfig config = new ClientConfig();
        Client client = ClientBuilder.newClient(config);

        WebTarget target = client.target(getBaseURI());

        Response vResponse = target.path("request").
                request().
                accept(MediaType.APPLICATION_JSON_TYPE).
                get(Response.class);

        return vResponse;
    }

    private static URI getBaseURI() {
        return UriBuilder.fromUri("").build();
    }
}
