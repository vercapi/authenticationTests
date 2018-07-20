package be.vercapi.adfoauth.view;

import java.io.IOException;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LoginServlet
	extends HttpServlet
{
	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp)
		throws ServletException
	{
		try
		{
			resp.sendRedirect("http://127.0.0.1:7101/OAuthEndPoint/OAuth?token=correct");
		}
		catch (IOException e)
		{
			LOG.log(Level.SEVERE, null, e);
		}

	}

	private static final Logger LOG = Logger.getLogger(LoginServlet.class.getName());
}
