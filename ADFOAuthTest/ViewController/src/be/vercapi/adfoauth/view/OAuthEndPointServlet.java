package be.vercapi.adfoauth.view;

import java.io.IOException;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import weblogic.security.URLCallbackHandler;
import weblogic.security.services.Authentication;

import weblogic.servlet.security.ServletAuthentication;

public class OAuthEndPointServlet
	extends HttpServlet
{
	@Override
		 protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException {
			  String vToken = (String)req.getParameter("token");
			  LOG.finest("Token: "+vToken);
			  if("correct".equals(vToken)){
					try {
						 LOG.finest("Trying to authenticate");
						 Subject subject = Authentication.login(new URLCallbackHandler("weblogic", "weblogic1"));
						 ServletAuthentication.runAs(subject, req);
					} catch (LoginException ex) {
						 LOG.log(Level.SEVERE, null, ex);
					}
			  }
			  
			  try
			  {
			     resp.sendRedirect(req.getContextPath()+"/faces/Home");
			  }
			  catch(IOException e)
			  {
			     LOG.log(Level.SEVERE, null, e);
			  }
			  
		 }
		 
		 private static final Logger LOG = Logger.getLogger(OAuthEndPointServlet.class.getName());
}
