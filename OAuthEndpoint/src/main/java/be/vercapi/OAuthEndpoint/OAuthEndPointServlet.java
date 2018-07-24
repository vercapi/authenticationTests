/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package be.vercapi.OAuthEndpoint;

import com.sun.corba.se.spi.presentation.rmi.StubAdapter;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import weblogic.security.SimpleCallbackHandler;

import weblogic.security.URLCallbackHandler;
import weblogic.security.services.Authentication;
import weblogic.servlet.security.ServletAuthentication;


/**
 *
 * @author vercapi
 */
public class OAuthEndPointServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String vToken = (String)req.getParameter("token");
        LOG.finest("Token: "+vToken);
        if("correct".equals(vToken)){
            try {
                LOG.finest("Trying to authenticate");
                Subject subject = Authentication.login(new SimpleCallbackHandler("weblogic", "weblogic1"));
                ServletAuthentication.runAs(subject, req);
                //ServletAuthentication.generateNewSessionID(req);
            } catch (LoginException ex) {
                LOG.log(Level.SEVERE, null, ex);
            }
        }
        
        resp.sendRedirect("http://127.0.0.1:7101/ADFOAuthTest-ViewController-context-root/faces/Home");
    }
    
    private static final Logger LOG = Logger.getLogger(OAuthEndPointServlet.class.getName());

}
