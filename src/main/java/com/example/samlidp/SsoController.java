package com.example.samlidp;

import com.example.samlidp.config.IdpConfiguration;
import com.example.samlidp.saml.SAMLAttribute;
import com.example.samlidp.saml.SAMLMessageHandler;
import com.example.samlidp.saml.SAMLPrincipal;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.validation.ValidationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

import static java.util.Collections.singletonList;
import static java.util.stream.Collectors.toList;

@Controller
public class SsoController {

  @Autowired
  private SAMLMessageHandler samlMessageHandler;

  @Autowired
  private IdpConfiguration idpConfiguration;

  @GetMapping("/SingleSignOnService")
  public void singleSignOnServiceGet(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication)
      throws IOException, MarshallingException, SignatureException, MessageEncodingException, ValidationException,
      SecurityException, MessageDecodingException, MetadataProviderException {

    doSSO(request, response, authentication, false);
  }

  @PostMapping("/SingleSignOnService")
  public void singleSignOnServicePost(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication)
      throws IOException, MarshallingException, SignatureException, MessageEncodingException, ValidationException,
      SecurityException, MessageDecodingException, MetadataProviderException {

    doSSO(request, response, authentication, true);
  }

  private void doSSO(HttpServletRequest request, HttpServletResponse response, Authentication authentication,
      boolean postRequest) throws ValidationException, SecurityException, MessageDecodingException,
      MarshallingException, SignatureException, MessageEncodingException, MetadataProviderException {

    SAMLMessageContext<?, ?, ?> messageContext = samlMessageHandler.extractSAMLMessageContext(request, response,
        postRequest);
    AuthnRequest authnRequest = (AuthnRequest) messageContext.getInboundSAMLMessage();

    SAMLPrincipal principal = new SAMLPrincipal(
        authentication.getName(),
        NameIDType.UNSPECIFIED,
        attributes(authentication.getName()),
        authnRequest.getIssuer().getValue(),
        authnRequest.getID(),
        authnRequest.getAssertionConsumerServiceURL(),
        messageContext.getRelayState());

    samlMessageHandler.sendAuthnResponse(principal, response);
  }

  private List<SAMLAttribute> attributes(String uid) {
    return idpConfiguration.getAttributes().entrySet().stream()
        .map(entry -> entry.getKey().equals("urn:mace:dir:attribute-def:uid")
            ? new SAMLAttribute(entry.getKey(), singletonList(uid))
            : new SAMLAttribute(entry.getKey(), entry.getValue()))
        .collect(toList());
  }

}
