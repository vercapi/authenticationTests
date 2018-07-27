package be.vercapi.oauth2provider;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

public class SimpleCallbackHandler implements  CallbackHandler{

    private String username;

    public SimpleCallbackHandler(String username) {
        this.username = username;
    }

	@Override
	public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
    for (int i = 0; i < callbacks.length; i++) {
 
      Callback callback = callbacks[i];
 
      // we only handle NameCallbacks
      if (!(callback instanceof NameCallback)) {
        throw new UnsupportedCallbackException(callback, "Unrecognized Callback");
      }
 
      // send the user name to the name callback:
      NameCallback nameCallback = (NameCallback)callback;
      nameCallback.setName(username);
    }
	}
}
