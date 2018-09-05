package be.vercapi.oauth2provider;

public interface OAuthAuthenticationMBean extends weblogic.management.commo.StandardInterface,weblogic.descriptor.DescriptorBean, weblogic.management.security.authentication.AuthenticatorMBean {
        
    public String getClientId();
    
    public void setClientId(String pClientId);
    
    public String getClientSecret();
    
    public void setClientSecret(String pClientSecret);
    
    public String getIntrospectionOpenidURL();
    
    public void setIntrospectionOpenidURL(String pURL);
}
