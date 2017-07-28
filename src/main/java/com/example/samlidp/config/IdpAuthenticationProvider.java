package com.example.samlidp.config;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import static com.example.samlidp.config.AuthenticationMethod.ALL;

import java.util.Arrays;

public class IdpAuthenticationProvider implements AuthenticationProvider {

  private final IdpConfiguration idpConfiguration;

  public IdpAuthenticationProvider(IdpConfiguration idpConfiguration) {
    this.idpConfiguration = idpConfiguration;
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    if (idpConfiguration.getAuthenticationMethod().equals(ALL)) {
      return new UsernamePasswordAuthenticationToken(authentication.getPrincipal(), authentication.getCredentials(),
          Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN"), new SimpleGrantedAuthority("ROLE_USER")));
    } else {
      return idpConfiguration.getUsers().stream()
          .filter(token -> token.getPrincipal().equals(authentication.getPrincipal())
              && token.getCredentials().equals(authentication.getCredentials()))
          .findFirst()
          .map(usernamePasswordAuthenticationToken -> new UsernamePasswordAuthenticationToken(
              // need top copy or else credentials are erased for future logins
              usernamePasswordAuthenticationToken.getPrincipal(), usernamePasswordAuthenticationToken.getCredentials(),
              usernamePasswordAuthenticationToken.getAuthorities()))
          .orElseThrow(() -> new AuthenticationException("User not found or bad credentials") {
            private static final long serialVersionUID = 1L;
          });
    }
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
  }
}
