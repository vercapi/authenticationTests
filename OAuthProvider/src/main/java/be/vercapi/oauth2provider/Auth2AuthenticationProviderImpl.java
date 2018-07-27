/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package be.vercapi.oauth2provider;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;

import weblogic.i18n.logging.NonCatalogLogger;
import weblogic.management.security.ProviderMBean;
import weblogic.security.provider.PrincipalValidatorImpl;
import weblogic.security.service.ContextHandler;
import weblogic.security.spi.AuthenticationProviderV2;
import weblogic.security.spi.IdentityAsserterV2;
import weblogic.security.spi.IdentityAssertionException;
import weblogic.security.spi.PrincipalValidator;
import weblogic.security.spi.SecurityServices;

/**
 *
 * @author vercapi
 */
public class Auth2AuthenticationProviderImpl implements AuthenticationProviderV2, IdentityAsserterV2 {

  private NonCatalogLogger logger = new NonCatalogLogger("OAUTHSEC");

  private String description; // a description of this provider
  private String OAuthURL; //URL Of the OAuth server

  private LoginModuleControlFlag controlFlag; // how this provider's login module should be used during the JAAS login

  @Override
  public AppConfigurationEntry getLoginModuleConfiguration() {
      return null;
  }

  @Override
  public AppConfigurationEntry getAssertionModuleConfiguration() {
      return null;
  }

  @Override
  public PrincipalValidator getPrincipalValidator() {
    return new PrincipalValidatorImpl();
  }

  @Override
  public IdentityAsserterV2 getIdentityAsserter() {
    return this;
  }

  @Override
  public void initialize(ProviderMBean pmb, SecurityServices ss) {
    OAuthAuthenticationMBean vMBean = (OAuthAuthenticationMBean) pmb;

    description = vMBean.getDescription();
  }

  @Override
  public String getDescription() {
    return description;
  }

  @Override
  public void shutdown() {
    logger.debug("Auth2AuthenticationPorviderImpl shutdown");
  }

  @Override
  public CallbackHandler assertIdentity(String type, Object token, ContextHandler contextHandler)
      throws IdentityAssertionException {
    System.out.println("Asserting Identity");
    if (OAuth2AsserterTokenTypes.OAuthToken.equals(type)) {
      System.out.println("Checking token: "+token);
      if ("correct".equals(token)) {
        return new SimpleCallbackHandler("weblogic");
      }
    }

    throw new IdentityAssertionException("Could not validate token: \"" + token + "\" of type: " + type);
  }
}
