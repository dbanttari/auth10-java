package com.auth10.federation;

import java.nio.file.Files;
import java.nio.file.Paths;

import org.junit.Test;

import junit.framework.TestCase;

public class ColdfusionTest extends TestCase {

	@Test
	public void testMattXml() throws Exception {
		String wsresult = new String(Files.readAllBytes(Paths.get("src","test","resources","matt.xml")));
		FederatedConfiguration.getInstance(Paths.get("src","test","resources","federation.properties"));
		FederatedPrincipal principal = new SamlTokenValidator().validate(wsresult);
		System.out.println(principal.getName());
		System.out.println(principal.getClaims().size() + " claim(s):");		
		for( Claim claim : principal.getClaims() ) {
			System.out.println(claim.toString());
		}
	}
	
}
