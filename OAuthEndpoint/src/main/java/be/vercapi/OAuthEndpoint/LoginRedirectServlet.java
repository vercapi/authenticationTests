/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package be.vercapi.OAuthEndpoint;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 *
 * @author vercapi
 */
public class LoginRedirectServlet extends HttpServlet {

    static URI getRedirectURI(){
        try {
            return new URI(OAuthProperties.REDIRECTION_URI.getValue());
        } catch (URISyntaxException ex) {
            LOG.log(Level.SEVERE, null, ex);
            return null;
        }
    }
    
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException {
        try {
            LOG.finest("Session ID: "+req.getSession().getId());
            String vState = UUID.randomUUID().toString();
            req.getSession().setAttribute(OAuthEndPointServlet.STATE, vState);
            resp.sendRedirect(OAuthProperties.AUTHORIZATION_URI.getValue()+"?client_id="+OAuthProperties.CLIENT_ID.getValue()+"&scope=auth_a_hat openid email profile&response_type=code&token_content_type=jwt&state="+vState+"&redirect_uri="+URLEncoder.encode(getRedirectURI().toString(), "UTF-8"));
            
            req.getSession().setAttribute(OAuthEndPointServlet.REDIRECT, req.getHeader("referer"));
        } catch (IOException e) {
            LOG.log(Level.SEVERE, null, e);
        }
    }

    private static final Logger LOG = Logger.getLogger(LoginRedirectServlet.class.getName());
}
