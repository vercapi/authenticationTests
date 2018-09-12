/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package be.vercapi.OAuthEndpoint;

import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.CacheControl;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import org.glassfish.jersey.client.ClientConfig;
import org.json.JSONObject;

import weblogic.security.services.Authentication;
import weblogic.servlet.security.ServletAuthentication;


/**
 *
 * @author vercapi
 */
public class OAuthEndPointServlet extends HttpServlet {
    
    //Callback attributes
    final static String STATE = "state";
    private final static String CODE = "code";
    private final static String ERROR = "error";
    
    //Token request attributes
    private final static String ACCESS_TOKEN = "access_token";
    private final static String TOKEN_TPYE = "token_type";
    private final static String EXPIRES_IN = "expires_in";
    private final static String SCOPE = "scope";
    
    //URL Session parameter
    final static String REDIRECT = "redirect";
    final static String TOKEN ="token";

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String vCode = (String)req.getParameter(CODE);
        
        String vRequestState = (String)req.getParameter(STATE);
        String vSessionState = (String)req.getSession().getAttribute(STATE);
        
        LOG.finest("Code: "+vCode);
        LOG.finest("Request Secret: "+vRequestState);
        LOG.finest("Session Secret: "+vSessionState);
        LOG.finest("Session ID: "+req.getSession().getId());
        try {
            LOG.finest("Trying to authenticate");
            if(!isRequestCorrect(vRequestState, vSessionState)){
                throw new LoginException("Secret is not correct");
            }
            
            String vToken = getToken(vCode, LoginRedirectServlet.getRedirectURI().toString());
            LOG.finest("Token: "+vToken);
            req.getSession().setAttribute(TOKEN, vToken);
            
            Subject subject = Authentication.assertIdentity("OAuthToken", vToken);
            ServletAuthentication.runAs(subject, req);
            //ServletAuthentication.generateNewSessionID(req);
        } catch (LoginException ex) {
            LOG.log(Level.SEVERE, null, ex);
        }
        
        String vRedirect  = (String)req.getSession().getAttribute(REDIRECT);
        LOG.finest(vRedirect);
        resp.sendRedirect(vRedirect);
    }
    
    private static final Logger LOG = Logger.getLogger(OAuthEndPointServlet.class.getName());
    
    private boolean isRequestCorrect(String pRequestSecret, String pSessionSecret){
        return pRequestSecret != null && pRequestSecret.equals(pSessionSecret);
    }
    
    private String getToken(String pCode, String pRedirectURI){
        LOG.finest("Redirect URL: "+pRedirectURI);
        ClientConfig config = new ClientConfig();
        Client client = ClientBuilder.newClient(config);

        WebTarget target = client.target(getBaseURI());
        
        
        MultivaluedMap<String, String> vFormData = new MultivaluedHashMap<String, String>();
        vFormData.add("grant_type", "authorization_code");
        vFormData.add("redirect_uri", pRedirectURI);
        vFormData.add("code", pCode);
        vFormData.add("client_id", OAuthProperties.CLIENT_ID.getValue());
        vFormData.add("client_secret", OAuthProperties.CLIENT_SECRET.getValue());
        Entity vForm = Entity.form(vFormData);

        Response vResponse = target.path("token")
                .request()
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + pCode)
                .header("redirect_uri", target)
                .cacheControl(CacheControl.valueOf("no-cache"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Postman-Token", "700c5636-f19e-47b1-93bb-7b318e1b253a")
                .accept(MediaType.APPLICATION_JSON_TYPE)
                .post(vForm, Response.class);   
        
        String vBody = vResponse.readEntity(String.class);
        LOG.finest("Body: "+vBody);
        JSONObject vJson = new JSONObject(vBody);
        return (String)vJson.get(ACCESS_TOKEN);
    }
    
    private static URI getBaseURI() {
        return UriBuilder.fromUri(OAuthProperties.TOKEN_URI.getValue()).build();
    }

}
