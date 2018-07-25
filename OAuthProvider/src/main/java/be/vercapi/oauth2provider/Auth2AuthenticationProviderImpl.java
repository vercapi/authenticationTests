/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package be.vercapi.oauth2provider;

import java.util.HashMap;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;

import weblogic.i18n.logging.NonCatalogLogger;
import weblogic.management.security.ProviderMBean;
import weblogic.security.provider.PrincipalValidatorImpl;
import weblogic.security.spi.AuthenticationProviderV2;
import weblogic.security.spi.IdentityAsserterV2;
import weblogic.security.spi.PrincipalValidator;
import weblogic.security.spi.SecurityServices;

/**
 *
 * @author vercapi
 */
public class Auth2AuthenticationProviderImpl implements AuthenticationProviderV2 {

    private NonCatalogLogger logger = new NonCatalogLogger("OAUTHSEC");

    private String description; // a description of this provider
    private String OAuthURL; //URL Of the OAuth server

    private LoginModuleControlFlag controlFlag; // how this provider's login module should be used during the JAAS login

    @Override
    public AppConfigurationEntry getLoginModuleConfiguration() {
        HashMap<String, Object> options = new HashMap<String, Object>();
        return getConfiguration(options);
    }

    @Override
    public AppConfigurationEntry getAssertionModuleConfiguration() {
        HashMap<String, Object> options = new HashMap<String, Object>();
        return getConfiguration(options);
    }

    @Override
    public PrincipalValidator getPrincipalValidator() {
        return new PrincipalValidatorImpl();
    }

    @Override
    public IdentityAsserterV2 getIdentityAsserter() {
        return null;
    }

    @Override
    public void initialize(ProviderMBean pmb, SecurityServices ss) {
        OAuthAuthenticationMBean vMBean = (OAuthAuthenticationMBean) pmb;
        
        description = vMBean.getDescription() ;

        String flag = vMBean.getControlFlag();
        if (flag.equalsIgnoreCase("REQUIRED")) {
            controlFlag = LoginModuleControlFlag.REQUIRED;
        } else if (flag.equalsIgnoreCase("OPTIONAL")) {
            controlFlag = LoginModuleControlFlag.OPTIONAL;
        } else if (flag.equalsIgnoreCase("REQUISITE")) {
            controlFlag = LoginModuleControlFlag.REQUISITE;
        } else if (flag.equalsIgnoreCase("SUFFICIENT")) {
            controlFlag = LoginModuleControlFlag.SUFFICIENT;
        } else {
            throw new IllegalArgumentException("invalid flag value" + flag);
        }
    }

    @Override
    public String getDescription() {
        return description;
    }

    @Override
    public void shutdown() {
        logger.debug("Auth2AuthenticationPorviderImpl shutdown");
    }

    private AppConfigurationEntry getConfiguration(HashMap<String, Object> options) {
        options.put("OAuthURL", OAuthURL);

        return new AppConfigurationEntry("be.vercapi.oauth2provider.Auth2LoginModule", controlFlag, options);
    }
    
}
