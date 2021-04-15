//-----------------------------------------------------------------------
// <copyright file="FederatedConfiguration.java" company="Microsoft">
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
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;

public class FederatedConfiguration extends Properties {

	private static final long serialVersionUID = -7599561834542465499L;
	private static FederatedConfiguration instance = null;
	private List<URI> uris = null;
	private static Path propsPath = null;

	public static FederatedConfiguration getInstance() throws IOException {
		return new FederatedConfiguration();
	}

	public static FederatedConfiguration getInstance(String path) throws IOException {
		if(propsPath != null) {
			Path _path = Paths.get(path);
			if(!propsPath.equals(_path)) {
				instance = null; // make new instance, path changed
				propsPath = _path;
			}
		}
		else {
			propsPath = Paths.get(path);
		}
		if (instance == null) {
			synchronized (FederatedConfiguration.class) {
				instance = new FederatedConfiguration();
			}
		}
		return instance;
		
	}
	
	private FederatedConfiguration() throws IOException {
		if (propsPath == null) {
			try (InputStream is = FederatedConfiguration.class.getResourceAsStream("/federation.properties")) {
				load(is);
			} catch (IOException e) {
				throw new IOException("Configuration could not be loaded", e);
			}
		}
		else {
			try (InputStream is = Files.newInputStream(propsPath)) {
				load(is);
			} catch (IOException e) {
				throw new IOException("Configuration could not be loaded", e);
			}
		}
	}

	public String getStsUrl() {
		return getProperty("federation.trustedissuers.issuer");
	}

	public String getStsFriendlyName() {
		return getProperty("federation.trustedissuers.friendlyname");
	}

	public String getRealm() {
		return getProperty("federation.realm");
	}

	public String getReply() {
		return getProperty("federation.reply");
	}

	public Boolean getEnableManualRedirect() {
		String manual = getProperty("federation.enableManualRedirect");
		if (manual != null && Boolean.parseBoolean(manual)) {
			return true;
		}
		return false;
	}

	public void setThumbprint(String thumbprint) {
		setProperty("federation.trustedissuers.thumbprint", thumbprint);
	}

	public String getThumbprint() {
		return getProperty("federation.trustedissuers.thumbprint");
	}

	public void setTrustedIssuers(String issuers) {
		if ( issuers == null  ) {
			setProperty("federation.trustedissuers.subjectname", "");
		}
		else {
			setProperty("federation.trustedissuers.subjectname", issuers);
		}
	}

	public String[] getTrustedIssuers() {
		String trustedIssuers = getProperty("federation.trustedissuers.subjectname");

		if (trustedIssuers == null)
			return new String[0];
		else
			return trustedIssuers.split("\\|");
	}

	public void setAudienceURI(String uris) {
		setProperty("federation.audienceuris", uris);
		this.uris = null;
	}

	public List<URI> getAudienceUris() throws URISyntaxException {
		if (uris == null) {
			uris = new LinkedList<URI>();
			if (containsKey("federation.audienceuris")) {
				for (String uri : getProperty("federation.audienceuris").split("\\|")) {
					uris.add(new URI(uri));
				}
			}
		}
		return uris;
	}

	public String getPrivateKeyPath() {
		return getProperty("federation.privateKeyFile");
	}
}
