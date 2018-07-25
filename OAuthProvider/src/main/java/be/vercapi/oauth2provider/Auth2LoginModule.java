package be.vercapi.oauth2provider;

import java.io.IOException;
import java.util.Map;
import java.util.Vector;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import weblogic.logging.NonCatalogLogger;
import weblogic.security.principal.WLSAbstractPrincipal;
import weblogic.security.principal.WLSGroupImpl;
import weblogic.security.principal.WLSUserImpl;

final public class Auth2LoginModule implements LoginModule {

  private NonCatalogLogger logger = new NonCatalogLogger("OAUTHSEC");

  private Subject subject; // the subject for this login
  private CallbackHandler callbackHandler; // where to get user names, passwords, ... for this login
  private boolean isIdentityAssertion; // are we in authentication or identity assertion mode?

  // Authentication status
  private boolean loginSucceeded; // have we successfully logged in?
  private boolean principalsInSubject; // did we add principals to the subject?
  private Vector<WLSAbstractPrincipal> principalsForSubject = new Vector<WLSAbstractPrincipal>(); // if so, what principals did we add to the subject

  @Override
  public boolean abort() throws LoginException {
    logger.debug("DBUserLoginModuleImpl.abort");
    if (principalsInSubject) {
      subject.getPrincipals().removeAll(principalsForSubject);
      principalsInSubject = false;
    }
    return true;
  }

  @Override
  public boolean commit() throws LoginException {
      logger.debug("OAuthserLoginModule commit");
      if (loginSucceeded) {
          // put the user and the user's groups (computed during the
          // login method and stored in the principalsForSubject object)
          // into the subject.
          subject.getPrincipals().addAll(principalsForSubject);
          principalsInSubject = true;
          return true;
      } else {
          return false;
      }
  }

  @Override
  public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
      Map<String, ?> options) {
      // only called (once!) after the constructor and before login

      logger.debug("OAuthLoginModuleImpl.initialize");
      this.subject = subject;
      this.callbackHandler = callbackHandler;
      
      // Determine if we're in identity assertion or authentication mode
      isIdentityAssertion =
          "true".equalsIgnoreCase((String)options.get("IdentityAssertion"));
      
  }
    
  @Override
  public boolean login() throws LoginException {
      // only called (once!) after initialize

        logger.debug("DBUserLoginModuleImpl.login");

        System.out.println("Hello from login module");

        // loginSucceeded      should be false
        // principalsInSubject should be false

        // Call a method to get the callbacks.
        // For authentication mode, it will have one for the
        // username and one for the password.
        // For identity assertion mode, it will have one for
        // the user name.
        Callback[] callbacks = getCallbacks();

        // Get the user name.
        String userName = getUserName(callbacks);

        if (userName.length() > 0) {
            // We have a user name

            boolean success = "correct".equals(userName);
            if (! success) {
                throwFailedLoginException("Authentication Failed: User " +
                                          userName + " doesn't exist or invalid password.");
            }
        }
        loginSucceeded = true;
        // since the login succeeded, add the user and its groups to the
        // list of principals we want to add to the subject.
        principalsForSubject.add(new WLSUserImpl(userName));
        addGroupsForSubject(userName);
        logger.info("Result of login:" + loginSucceeded);
        return loginSucceeded;
  }

  @Override
  public boolean logout() throws LoginException {
    return false;
  }

      /**
     * Get the list of callbacks needed by the login module.
     *
     * @return The array of Callback objects by the login module.
     * Returns one for the user name and password if in authentication mode.
     * Returns one for the user name if in identity assertion mode.
     */
    private Callback[] getCallbacks() throws LoginException {
        if (callbackHandler == null) {
            throwLoginException("No CallbackHandler Specified");
        }

        Callback[] callbacks;
        if (isIdentityAssertion) {
            callbacks = new Callback[1]; // need one for the user name
        } else {
            callbacks =
                    new Callback[2]; // need one for the user name and one for the password

            // add in the password callback
            callbacks[1] = new PasswordCallback("password: ", false);
        }

        // add in the user name callback
        callbacks[0] = new NameCallback("username: ");

        // Call the callback handler, who in turn, calls back to the
        // callback objects, handing them the user name and password.
        // These callback objects hold onto the user name and password.
        // The login module retrieves the user name and password from them later.
        try {
            callbackHandler.handle(callbacks);
        } catch (IOException e) {
            throw new LoginException(e.toString());
        } catch (UnsupportedCallbackException e) {
            throwLoginException(e.toString() + " " +
                                e.getCallback().toString());
        }

        return callbacks;
    }
    
    /**
     * Throw an invalid login exception.
     *
     * @param msg A String containing the text of the LoginException.
     *
     * @throws LoginException
     */
    private void throwLoginException(String msg) throws LoginException {
        logger.warning("Throwing LoginException(" + msg + ")");
        throw new LoginException(msg);
    }

    /**
     * Throws a failed login excception.
     *
     * @param msg A String containing the text of the FailedLoginException.
     *
     * @throws LoginException
     */
    private void throwFailedLoginException(String msg) throws FailedLoginException {
        logger.warning("Throwing FailedLoginException(" + msg + ")");
        throw new FailedLoginException(msg);
    }

    /**
     * Get the user name from the callbacks (that the callback handler
     * has already handed the user name to).
     *
     * @param callbacks The array of Callback objects used by this login module.
     * The first in the list must be the user name callback object.
     *
     * @return A String containing the user name (from the user name callback object)
     */
    private String getUserName(Callback[] callbacks) throws LoginException {
        String userName = ((NameCallback)callbacks[0]).getName();
        if (userName == null) {
            throwLoginException("Username not supplied.");
        }
        logger.info("\tuserName\t= " + userName);
        return userName;
    }

    /**
     * Add the user's groups to the list of principals to be added to the subject.
     *
     * @param userName A String containing the user name the user's name.
     */
    private void addGroupsForSubject(String userName) {
        // Get the user's list of groups (recursively - so, if user1 is a member
        // of group1 and group1 is a member of group2, then it returns group1 and
        // group2).  Iterate over the groups, adding each to the list of principals
        // to add to the subject.
        principalsForSubject.add(new WLSGroupImpl("secret-group"));
    }

}
