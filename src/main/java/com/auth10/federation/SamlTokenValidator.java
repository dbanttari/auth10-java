//-----------------------------------------------------------------------
// <copyright file="SamlTokenValidator.java" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
//
// 
//    Copyright 2012 Microsoft Corporation
//    All rights reserved.
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//      http://www.apache.org/licenses/LICENSE-2.0
//
// THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, 
// EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION ANY IMPLIED WARRANTIES OR 
// CONDITIONS OF TITLE, FITNESS FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
//
// See the Apache Version 2.0 License for specific language governing 
// permissions and limitations under the License.
// </copyright>
//
// <summary>
//     
//
// </summary>
//----------------------------------------------------------------------------------------------

package com.auth10.federation;

import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;

import org.joda.time.Duration;
import org.joda.time.Instant;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityTestHelper;
import org.opensaml.xml.security.credential.CollectionCredentialResolver;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.criteria.EntityIDCriteria;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.impl.ExplicitKeySignatureTrustEngine;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

@SuppressWarnings("deprecation")
public class SamlTokenValidator {
	public static final int MAX_CLOCK_SKEW_IN_MINUTES = 3;
	private boolean validateExpiration = true;
	private final FederatedConfiguration config;

	public SamlTokenValidator() throws ConfigurationException, URISyntaxException {
		this(FederatedConfiguration.getInstance());
	}

	public SamlTokenValidator(FederatedConfiguration config) throws ConfigurationException {
		super();
		this.config = config;
		DefaultBootstrap.bootstrap();
	}

	public boolean getValidateExpiration() {
		return validateExpiration;
	}

	public void setValidateExpiration(boolean value) {
		this.validateExpiration = value;
	}

	public FederatedPrincipal validate(String envelopedToken)
			throws Exception {
	
		SignableSAMLObject samlToken;
		
		if (envelopedToken.contains("RequestSecurityTokenResponse")) {
			samlToken = getSamlTokenFromRstr(envelopedToken);
		} else {
			samlToken = getSamlTokenFromSamlResponse(envelopedToken);
		}

		boolean valid = validateToken(samlToken);
		
		if (!valid) {
			throw new FederationException("Invalid signature");
		}

		boolean trusted = false;

		for (String issuer : config.getTrustedIssuers()) {
			trusted |= validateIssuerUsingSubjectName(samlToken, issuer);
		}

		if (!trusted && (config.getThumbprint() != null)) {
			trusted = validateIssuerUsingCertificateThumbprint(samlToken,
					config.getThumbprint());
		}

		if (!trusted) {
			throw new FederationException(
					"The token was issued by an authority that is not trusted");
		}

		String address = null;
		if (samlToken instanceof org.opensaml.saml1.core.Assertion) {
			address = getAudienceUri((org.opensaml.saml1.core.Assertion) samlToken);
		}
		else if (samlToken instanceof org.opensaml.saml2.core.Assertion) {
			address = getAudienceUri((org.opensaml.saml2.core.Assertion) samlToken);
		}

		URI audience = new URI(address);

		boolean validAudience = false;
		for (URI audienceUri : config.getAudienceUris()) {
			validAudience |= audience.equals(audienceUri);
		}

		if (!validAudience) {
			throw new FederationException(String.format("The token applies to an untrusted audience: %s", new Object[] { audience }));
		}

		List<Claim> claims = null;
		if (samlToken instanceof org.opensaml.saml1.core.Assertion) {
			claims = getClaims((org.opensaml.saml1.core.Assertion) samlToken);
		}

		if (samlToken instanceof org.opensaml.saml2.core.Assertion) {
			claims = getClaims((org.opensaml.saml2.core.Assertion) samlToken);
		}

		if (this.validateExpiration) {

			boolean expired = false;
			if (samlToken instanceof org.opensaml.saml1.core.Assertion) {
				Instant notBefore = ((org.opensaml.saml1.core.Assertion) samlToken).getConditions().getNotBefore().toInstant();
				Instant notOnOrAfter = ((org.opensaml.saml1.core.Assertion) samlToken).getConditions().getNotOnOrAfter().toInstant();
				expired = validateExpiration(notBefore, notOnOrAfter);
			}
			else if (samlToken instanceof org.opensaml.saml2.core.Assertion) {
				Instant notBefore = ((org.opensaml.saml2.core.Assertion) samlToken).getConditions().getNotBefore().toInstant();
				Instant notOnOrAfter = ((org.opensaml.saml2.core.Assertion) samlToken).getConditions().getNotOnOrAfter().toInstant();
				expired = validateExpiration(notBefore, notOnOrAfter);
			}

			if (expired) {
				throw new FederationException("The token has been expired");
			}
		}

		FederatedPrincipal ret;
		try {
			String name;
			if (samlToken instanceof org.opensaml.saml1.core.Assertion) {
				name = ((org.opensaml.saml1.core.Assertion)samlToken).getAuthenticationStatements().get(0).getSubject().getNameIdentifier().getNameIdentifier();
			}
			else { // if (samlToken instanceof org.opensaml.saml2.core.Assertion)
				name = ((org.opensaml.saml2.core.Assertion)samlToken).getSubject().getNameID().getValue();
			}
			ret = new FederatedPrincipal(name, claims);
		}
		catch(IndexOutOfBoundsException x) {
			ret = new FederatedPrincipal(claims);
		}
		catch(NullPointerException x) {
			ret = new FederatedPrincipal(claims);			
		}
		
		return ret;
	}

	private static SignableSAMLObject getSamlTokenFromSamlResponse(
			String samlResponse) throws ParserConfigurationException,
			SAXException, IOException, UnmarshallingException {
		Document document = getDocument(samlResponse);

		Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(document.getDocumentElement());
		org.opensaml.saml2.core.Response response = (org.opensaml.saml2.core.Response) unmarshaller.unmarshall(document.getDocumentElement());
		SignableSAMLObject samlToken = (SignableSAMLObject) response.getAssertions().get(0);

		return samlToken;
	}

	private static SignableSAMLObject getSamlTokenFromRstr(String rstr)
			throws Exception {
		
		Document document = getDocument(rstr);
		NodeList nodes = extractViaXpath(document, "//*[local-name() = 'EncryptedData']");
		if(nodes.getLength() != 0) {
			document = decodeEncryptedResponse(document);
		}

		nodes = extractViaXpath(document, "//*[local-name() = 'Assertion']");

		if (nodes.getLength() == 0) {
			throw new FederationException("SAML token was not found");
		}

		Element samlTokenElement = (Element) nodes.item(0);
		Unmarshaller unmarshaller = Configuration.getUnmarshallerFactory().getUnmarshaller(samlTokenElement);
		SignableSAMLObject samlToken = (SignableSAMLObject) unmarshaller.unmarshall(samlTokenElement);

		return samlToken;
	}

	private static NodeList extractViaXpath(Document document, String xpathstr) {
		NodeList nodes = null;

		try {
			XPath xpath = XPathFactory.newInstance().newXPath();
			XPathExpression expression = xpath.compile(xpathstr);
			nodes = (NodeList) expression.evaluate(document.getDocumentElement(), XPathConstants.NODESET);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return nodes;
	}

	public static RSAPrivateKey readPrivateKey(Path path) throws Exception {
	    String key = new String(Files.readAllBytes(path), Charset.defaultCharset());

	    String privateKeyPEM = key
	      .replace("-----BEGIN PRIVATE KEY-----", "")
	      .replaceAll("\r", "")
	      .replaceAll("\n", "")
	      .replace("-----END PRIVATE KEY-----", "");

	    byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);

	    KeyFactory keyFactory = KeyFactory.getInstance("rsa");
	    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
	    return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
	}
	
	private static Document decodeEncryptedResponse(Document doc) throws Exception {
		 NodeList ciphers = doc.getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#", "CipherValue");
		 String aesPasswordEncrypted = ciphers.item(0).getTextContent().trim();
		 String samlTokenEncrypted = ciphers.item(1).getTextContent().trim();

		 // Decrypt the password for the SAML token.
		 RSAPrivateKey privateKey = readPrivateKey(Paths.get("src","test","resources","privatekey.pem"));
		 Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
		 cipher.init(Cipher.DECRYPT_MODE, privateKey);
		 byte[] decoded = Base64.getDecoder().decode(aesPasswordEncrypted);
		 byte[] aesPassword = cipher.doFinal(decoded);
		 
		 // Decrypt the SAML token.
		 Key aesKey = new SecretKeySpec(aesPassword, "AES");
		 cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		 decoded = Base64.getDecoder().decode(samlTokenEncrypted);
		 IvParameterSpec ivParameterSpec=new IvParameterSpec(Arrays.copyOfRange(decoded, 0, 16));
		 cipher.init(Cipher.DECRYPT_MODE, aesKey, ivParameterSpec);
		 byte[] decrypted = cipher.doFinal(decoded);
		 String saml = new String(decrypted, 16, decrypted.length-16, "UTF-8");
		 
		 // Parse the XML and return the token.
		 return getDocument(saml);
	}

	private static String getAudienceUri(
			org.opensaml.saml2.core.Assertion samlAssertion) {
		org.opensaml.saml2.core.Audience audienceUri = samlAssertion.getConditions().getAudienceRestrictions().get(0)
				.getAudiences().get(0);
		return audienceUri.getAudienceURI();
	}

	private static String getAudienceUri(org.opensaml.saml1.core.Assertion samlAssertion) {
		
		org.opensaml.saml1.core.Audience audienceUri = samlAssertion.getConditions().getAudienceRestrictionConditions().get(0).getAudiences().get(0);
		return audienceUri.getUri();
	}

	private boolean validateExpiration(Instant notBefore, Instant notOnOrAfter) {
		
		Instant now = new Instant();
		Duration skew = new Duration(MAX_CLOCK_SKEW_IN_MINUTES * 60 * 1000);

		if (now.plus(skew).isBefore(notBefore)) {
			return true;
		}

		if (now.minus(skew).isAfter(notOnOrAfter)) {
			return true;
		}

		return false;
	}

	private static boolean validateToken(SignableSAMLObject samlToken)
			throws SecurityException, ValidationException,
			ConfigurationException, UnmarshallingException,
			CertificateException, KeyException {
		
		samlToken.validate(true);
		Signature signature = samlToken.getSignature();
		KeyInfo keyInfo = signature.getKeyInfo();
		X509Certificate pubKey = (X509Certificate) KeyInfoHelper
				.getCertificates(keyInfo).get(0);

		BasicX509Credential cred = new BasicX509Credential();
		cred.setEntityCertificate(pubKey);
		cred.setEntityId("signing-entity-ID");

		ArrayList<Credential> trustedCredentials = new ArrayList<Credential>();
		trustedCredentials.add(cred);

		CollectionCredentialResolver credResolver = new CollectionCredentialResolver(
				trustedCredentials);

		KeyInfoCredentialResolver kiResolver = SecurityTestHelper
				.buildBasicInlineKeyInfoResolver();
		ExplicitKeySignatureTrustEngine engine = new ExplicitKeySignatureTrustEngine(
				credResolver, kiResolver);

		CriteriaSet criteriaSet = new CriteriaSet();
		criteriaSet.add(new EntityIDCriteria("signing-entity-ID"));

		return engine.validate(signature, criteriaSet);
	}

	private static boolean validateIssuerUsingSubjectName(
			SignableSAMLObject samlToken, String subjectName)
			throws UnmarshallingException, ValidationException,
			CertificateException {
		
		Signature signature = samlToken.getSignature();
		KeyInfo keyInfo = signature.getKeyInfo();
		X509Certificate pubKey = KeyInfoHelper.getCertificates(keyInfo).get(0);

		String issuer = pubKey.getSubjectDN().getName();
		return issuer.equals(subjectName);
	}

	private static boolean validateIssuerUsingCertificateThumbprint(
			SignableSAMLObject samlToken, String thumbprint)
			throws UnmarshallingException, ValidationException,
			CertificateException, NoSuchAlgorithmException {
		
		Signature signature = samlToken.getSignature();
		KeyInfo keyInfo = signature.getKeyInfo();
		X509Certificate pubKey = KeyInfoHelper.getCertificates(keyInfo).get(0);

		String thumbprintFromToken = SamlTokenValidator
				.getThumbPrintFromCert(pubKey);

		return thumbprintFromToken.equalsIgnoreCase(thumbprint);
	}

	private static String getThumbPrintFromCert(X509Certificate cert)
			throws NoSuchAlgorithmException, CertificateEncodingException {
		
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		byte[] der = cert.getEncoded();
		md.update(der);
		byte[] digest = md.digest();
		return hexify(digest);
	}

	private static String hexify(byte bytes[]) {
		char[] hexDigits = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
				'a', 'b', 'c', 'd', 'e', 'f' };

		StringBuffer buf = new StringBuffer(bytes.length * 2);

		for (int i = 0; i < bytes.length; ++i) {
			buf.append(hexDigits[(bytes[i] & 0xf0) >> 4]);
			buf.append(hexDigits[bytes[i] & 0x0f]);
		}

		return buf.toString();
	}

	private static List<Claim> getClaims(
			org.opensaml.saml2.core.Assertion samlAssertion)
			throws SecurityException, ValidationException,
			ConfigurationException, UnmarshallingException,
			CertificateException, KeyException {
		
		ArrayList<Claim> claims = new ArrayList<Claim>();

		List<org.opensaml.saml2.core.AttributeStatement> attributeStmts = samlAssertion
				.getAttributeStatements();

		for (org.opensaml.saml2.core.AttributeStatement attributeStmt : attributeStmts) {
			List<org.opensaml.saml2.core.Attribute> attributes = attributeStmt
					.getAttributes();

			for (org.opensaml.saml2.core.Attribute attribute : attributes) {
				String claimType = attribute.getName();
				String claimValue = getValueFrom(attribute.getAttributeValues());
				claims.add(new Claim(claimType, claimValue));
			}
		}

		return claims;
	}

	private static List<Claim> getClaims(
			org.opensaml.saml1.core.Assertion samlAssertion)
			throws SecurityException, ValidationException,
			ConfigurationException, UnmarshallingException,
			CertificateException, KeyException {
		
		ArrayList<Claim> claims = new ArrayList<Claim>();

		List<org.opensaml.saml1.core.AttributeStatement> attributeStmts = samlAssertion.getAttributeStatements();

		for (org.opensaml.saml1.core.AttributeStatement attributeStmt : attributeStmts) {
			List<org.opensaml.saml1.core.Attribute> attributes = attributeStmt.getAttributes();

			for (org.opensaml.saml1.core.Attribute attribute : attributes) {
				String claimType = attribute.getAttributeNamespace() + "/" + attribute.getAttributeName();
				String claimValue = getValueFrom(attribute.getAttributeValues());
				claims.add(new Claim(claimType, claimValue));
			}
		}

		return claims;
	}

	private static String getValueFrom(List<XMLObject> attributeValues) {
				
		StringBuffer buffer = new StringBuffer();
		
		for (XMLObject value : attributeValues) {
			if (buffer.length() > 0)
				buffer.append(',');
			buffer.append(value.getDOM().getTextContent());
		}

		return buffer.toString();
	}

	private static Document getDocument(String doc)
			throws ParserConfigurationException, SAXException, IOException {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		DocumentBuilder documentbuilder = factory.newDocumentBuilder();
		return documentbuilder.parse(new InputSource(new StringReader(doc)));
	}

}
