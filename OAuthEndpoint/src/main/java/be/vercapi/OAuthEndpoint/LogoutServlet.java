/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package be.vercapi.OAuthEndpoint;

import java.io.IOException;
import java.net.URI;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.CacheControl;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import org.glassfish.jersey.client.ClientConfig;

/**
 *
 * @author vercapi
 */
public class LogoutServlet extends HttpServlet{
    
    private static final Logger LOG = Logger.getLogger(LogoutServlet.class.getName());
    
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        req.logout();
        
        //Invalidate token
        ClientConfig config = new ClientConfig();
        Client client = ClientBuilder.newClient(config);

        WebTarget target = client.target(getBaseURI());
        
        MultivaluedMap<String, String> vFormData = new MultivaluedHashMap<String, String>();
        vFormData.add("access_token", (String)req.getSession().getAttribute(OAuthEndPointServlet.TOKEN));
        vFormData.add("client_id", OAuthProperties.CLIENT_ID.getValue());
        vFormData.add("client_secret", OAuthProperties.CLIENT_SECRET.getValue());
        Entity vForm = Entity.form(vFormData);
        
        LOG.finest("TOKEN: "+ (String)req.getSession().getAttribute(OAuthEndPointServlet.TOKEN));
        
        Response vResponse = target.path("revoke")
                .request()
                .cacheControl(CacheControl.valueOf("no-cache"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .post(vForm, Response.class);
        
        String vBody = vResponse.readEntity(String.class);
        LOG.finest("Body: "+vBody);
        
        LOG.finest("REFERER: "+req.getHeader("referer"));
        resp.sendRedirect(req.getHeader("referer"));
    }
    
      private static URI getBaseURI() {
        return UriBuilder.fromUri(OAuthProperties.TOKEN_URI.getValue()).build();
    }
    
}
