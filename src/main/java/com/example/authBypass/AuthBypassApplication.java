package com.example.authBypass;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.zaproxy.clientapi.core.*;
import org.zaproxy.clientapi.gen.Context;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.regex.Pattern;

@SpringBootApplication
public class AuthBypassApplication {

	private static final String ZAP_ADDRESS = "localhost";
	private static final int ZAP_PORT = 8098;
	private static final String contextId = "1";
	private static final String contextName = "Default Context";
	private static final String target = "http://localhost:8090/bodgeit/";

	public static void main(String[] args) throws ClientApiException, UnsupportedEncodingException {
		ClientApi clientApi = new ClientApi(ZAP_ADDRESS, ZAP_PORT);

		spider(clientApi);
		setIncludeAndExcludeInContext(clientApi);
		System.out.println("Context Setup Finish");
		setFormBasedAuthentication(clientApi);
		setLoggedInIndicator(clientApi);
		String userId = setUserAuthConfig(clientApi);
		System.out.println("Current User ID : " + userId);
		scanAsUser(clientApi, userId);
		activeScan(clientApi);
	}

	private static void setIncludeAndExcludeInContext(ClientApi clientApi) throws ClientApiException {
		String includeContextUrl = "http://localhost:8090/bodgeit.*";
		String excludeContextUrl = "http://localhost:8090/bodgeit/logout.jsp";

		try {
			clientApi.context.context(contextName);
		} catch (ClientApiException e){
			System.out.println(e);
			System.out.println("Creating Context " + contextName);
			clientApi.context.newContext(contextName);
		}
		clientApi.context.includeInContext(contextName, includeContextUrl);
		clientApi.context.excludeFromContext(contextName, excludeContextUrl);
	}

	private static void setFormBasedAuthentication(ClientApi clientApi) throws ClientApiException {
		String loginUrl = "https://localhost:8090/bodgeit/login.jsp";
		String loginRequestData = "username={%username%}&password={%password%}";

		StringBuilder formBasedConfig = new StringBuilder();
		formBasedConfig.append("loginUrl=").append(URLEncoder.encode(loginUrl, StandardCharsets.UTF_8));
		formBasedConfig.append("&loginRequestData=").append(URLEncoder.encode(loginRequestData, StandardCharsets.UTF_8));

		System.out.println("Setting form based authentication configuration as :"
				+ formBasedConfig.toString());
		clientApi.authentication.setAuthenticationMethod(contextId, "formBasedAuthentication",
				formBasedConfig.toString());
		System.out.println("Authentication config: "
				+ clientApi.authentication.getAuthenticationMethod(contextId).toString(0));
	}

	private static void setLoggedInIndicator(ClientApi clientApi) throws ClientApiException {
		String loggedInIndicator = "<a href=\"logout.jsp\">Logout</a>";

		clientApi.authentication.setLoggedInIndicator(contextId, Pattern.quote(loggedInIndicator) );
		System.out.println("Configured logged in indicator regex: " + ((ApiResponseElement) clientApi.authentication.getLoggedInIndicator(contextId)).getValue());
	}

	private static String setUserAuthConfig(ClientApi clientApi) throws ClientApiException, UnsupportedEncodingException {
		String user = "Test";
		String username = "test@gmail.com";
		String password = "weakPass";

		String userId = extractUserId(clientApi.users.newUser(contextId, user));
		StringBuilder userAuthConfig = new StringBuilder();
		userAuthConfig.append("username=").append(URLEncoder.encode(username, "UTF-8"));
		userAuthConfig.append("&password=").append(URLEncoder.encode(password, "UTF-8"));

		System.out.println("Setting user authentication configuration as: " + userAuthConfig.toString());
		return userId;
	}

	private static String extractUserId(ApiResponse response) {
		return ((ApiResponseElement) response).getValue();
	}

	private static String convertObjToString(Object clsObj) {
		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		String prettyJson = gson.toJson(clsObj, new TypeToken<Object>() {
		}.getType());
		return prettyJson;
	}

	private static void spider(ClientApi clientApi) {
		try {
			// Start spidering the target
			System.out.println("Spidering target : " + target);
			ApiResponse resp = clientApi.spider.scan(target, null, null, null, null);
			String scanID;
			int progress;

			// The scan returns a scan id to support concurrent scanning
			scanID = ((ApiResponseElement) resp).getValue();
			// Poll the status until it completes
			while (true) {
				Thread.sleep(1000);
				progress = Integer.parseInt(((ApiResponseElement) clientApi.spider.status(scanID)).getValue());
				System.out.println("Spider progress : " + progress + "%");
				if (progress >= 100) {
					break;
				}
			}
			System.out.println("Spider completed");
			// If required post process the spider results
			List<ApiResponse> spiderResults = ((ApiResponseList) clientApi.spider.results(scanID)).getItems();
			System.out.println(convertObjToString(spiderResults));

			// TODO: Explore the Application more with Ajax Spider or Start scanning the application for vulnerabilities

		} catch (Exception e) {
			System.out.println("Exception : " + e.getMessage());
			e.printStackTrace();
		}
	}

	private static void scanAsUser(ClientApi clientApi, String userId) throws ClientApiException {
		try {
			// Start spidering the target
			System.out.println("Spidering target : " + target);
			ApiResponse resp = clientApi.spider.scanAsUser(contextId, userId, target, null, "true", null);
			String scanID;
			int progress;

			// The scan returns a scan id to support concurrent scanning
			scanID = ((ApiResponseElement) resp).getValue();
			// Poll the status until it completes
			while (true) {
				Thread.sleep(1000);
				progress = Integer.parseInt(((ApiResponseElement) clientApi.spider.status(scanID)).getValue());
				System.out.println("Spider progress : " + progress + "%");
				if (progress >= 100) {
					break;
				}
			}
			System.out.println("Spider completed");
			// If required post process the spider results
			List<ApiResponse> spiderResults = ((ApiResponseList) clientApi.spider.results(scanID)).getItems();
			System.out.println(convertObjToString(spiderResults));

			// TODO: Explore the Application more with Ajax Spider or Start scanning the application for vulnerabilities

		} catch (Exception e) {
			System.out.println("Exception : " + e.getMessage());
			e.printStackTrace();
		}
	}

	private static void activeScan(ClientApi clientApi) {
		try {
			// TODO : explore the app (Spider, etc) before using the Active Scan API, Refer the explore section
			System.out.println("Active Scanning target : " + target);
			ApiResponse resp = clientApi.ascan.scan(target, "True", "False", null, null, null);
			String scanid;
			int progress;

			// The scan now returns a scan id to support concurrent scanning
			scanid = ((ApiResponseElement) resp).getValue();
			// Poll the status until it completes
			while (true) {
				Thread.sleep(5000);
				progress =
						Integer.parseInt(
								((ApiResponseElement) clientApi.ascan.status(scanid)).getValue());
				System.out.println("Active Scan progress : " + progress + "%");
				if (progress >= 100) {
					break;
				}
			}

			System.out.println("Active Scan complete");
			// Print vulnerabilities found by the scanning
			System.out.println("Alerts:");
			System.out.println(new String(clientApi.core.jsonreport(), StandardCharsets.UTF_8));

		} catch (Exception e) {
			System.out.println("Exception : " + e.getMessage());
			e.printStackTrace();
		}
	}

}
