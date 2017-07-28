package com.example.samlidp.config;

import org.opensaml.xml.Configuration;
import org.opensaml.xml.security.BasicSecurityConfiguration;
import org.opensaml.xml.signature.SignatureConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.stereotype.Component;

import com.example.samlidp.saml.KeyStoreLocator;
import com.fasterxml.jackson.annotation.JsonIgnore;

import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

@Component
public class IdpConfiguration {

  @JsonIgnore
  protected final Logger LOG = LoggerFactory.getLogger(getClass());

  @JsonIgnore
  private JKSKeyManager keyManager;
  private String keystorePassword = "secret";
  private String entityId;
  private Map<String, List<String>> attributes = new TreeMap<>();
  private List<UsernamePasswordAuthenticationToken> users = new ArrayList<>();
  private AuthenticationMethod authenticationMethod;

  @Autowired
  public IdpConfiguration(JKSKeyManager keyManager, @Value("${idp.entity_id}") String entityId,
      @Value("${idp.private_key}") String idpPrivateKey, @Value("${idp.certificate}") String idpCertificate,
      @Value("${idp.auth_method}") String authMethod) {

    this.keyManager = keyManager;
    this.entityId = entityId;
    this.authenticationMethod = AuthenticationMethod.valueOf(authMethod);

    setKeyStore(entityId, idpPrivateKey, idpCertificate);
    setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);

    stubUsers();
    stubAttributes();
  }

  public String getEntityId() {
    return entityId;
  }

  public AuthenticationMethod getAuthenticationMethod() {
    return authenticationMethod;
  }

  public List<UsernamePasswordAuthenticationToken> getUsers() {
    return users;
  }

  public Map<String, List<String>> getAttributes() {
    return attributes;
  }

  private void setKeyStore(String alias, String privateKey, String certificate) {
    try {
      KeyStore keyStore = keyManager.getKeyStore();
      Enumeration<String> aliases = keyStore.aliases();
      while (aliases.hasMoreElements()) {
        keyStore.deleteEntry(aliases.nextElement());
      }
      KeyStoreLocator.addPrivateKey(keyStore, alias, privateKey, certificate, keystorePassword);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public void setSignatureAlgorithm(String signatureAlgorithm) {
    BasicSecurityConfiguration.class.cast(Configuration.getGlobalSecurityConfiguration())
        .registerSignatureAlgorithmURI("RSA", signatureAlgorithm);
  }

  private void stubUsers() {
    users.clear();
    UsernamePasswordAuthenticationToken admin = new UsernamePasswordAuthenticationToken("admin", "secret",
        Arrays.asList(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    UsernamePasswordAuthenticationToken user = new UsernamePasswordAuthenticationToken("user", "secret",
        Arrays.asList(new SimpleGrantedAuthority("ROLE_USER")));
    users.addAll(Arrays.asList(admin, user));
  }

  private void stubAttributes() {
    attributes.clear();
    putAttribute("urn:mace:dir:attribute-def:uid", "john.doe");
    putAttribute("urn:mace:dir:attribute-def:cn", "John Doe");
    putAttribute("urn:mace:dir:attribute-def:givenName", "John");
    putAttribute("urn:mace:dir:attribute-def:sn", "Doe");
    putAttribute("urn:mace:dir:attribute-def:displayName", "John Doe");
    putAttribute("urn:mace:dir:attribute-def:mail", "j.doe@example.com");
    putAttribute("urn:mace:terena.org:attribute-def:schacHomeOrganization", "example.com");
    putAttribute("urn:mace:dir:attribute-def:eduPersonPrincipalName", "j.doe@example.com");
  }

  private void putAttribute(String key, String... values) {
    this.attributes.put(key, Arrays.asList(values));
  }

}
