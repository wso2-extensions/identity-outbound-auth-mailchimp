package org.wso2.carbon.identity.authenticator.mailChimp;

import static org.mockito.Matchers.anyString;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.modules.testng.PowerMockTestCase;
import org.powermock.reflect.Whitebox;
import org.testng.Assert;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import static org.mockito.MockitoAnnotations.initMocks;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;

@RunWith(PowerMockRunner.class)
@PrepareForTest({OAuthAuthzResponse.class, AuthenticatedUser.class,
        OAuthClientRequest.class, URL.class})

public class MailChimpAuthenticatorTest extends PowerMockTestCase {

    @Mock
    private HttpServletRequest httpServletRequest;

    @Mock
    private HttpServletResponse httpServletResponse;

    @Spy
    private AuthenticationContext context = new AuthenticationContext();

    @Mock
    private OAuthClientResponse oAuthClientResponse;

    @Mock
    private OAuthClient mockOAuthClient;

    @Mock
    private OAuthClientRequest mockOAuthClientRequest;

    @Mock
    private OAuthJSONAccessTokenResponse oAuthJSONAccessTokenResponse;

    MailChimpAuthenticator mailChimpAuthenticator;

    @Mock
    private OAuthAuthzResponse authAuthzResponse;

    @Mock
    private OAuthClient oAuthClient;

    @DataProvider(name = "authenticatorProperties")
    public Object[][] getAuthenticatorPropertiesData() {
        Map<String, String> authenticatorProperties = new HashMap<>();
        authenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_ID, "test-client-id");
        authenticatorProperties.put(OIDCAuthenticatorConstants.CLIENT_SECRET, "test-client-secret");
        authenticatorProperties.put("callbackUrl", "http://localhost:9443/commonauth");

        return new Object[][]{{authenticatorProperties}};
    }

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new org.powermock.modules.testng.PowerMockObjectFactory();
    }

    @BeforeMethod
    public void setUp() {
        mailChimpAuthenticator = new MailChimpAuthenticator();
        initMocks(this);
    }

    @Test
    public void testGetName() {
        String name = mailChimpAuthenticator.getName();
        Assert.assertEquals("MailChimpAuthenticator", name);
    }

    @Test(description = "Test case for getAuthorizationServerEndpoint method", dataProvider = "authenticatorProperties")
    public void testGetAuthorizationServerEndpoint(Map<String, String> authenticatorProperties) throws Exception {
        String authorizationServerEndpoint = mailChimpAuthenticator
                .getAuthorizationServerEndpoint(authenticatorProperties);
        Assert.assertEquals(MailChimpAuthenticatorConstants.MailChimp_OAUTH_ENDPOINT, authorizationServerEndpoint);
    }

    @Test(description = "Test case for getTokenEndpoint method", dataProvider = "authenticatorProperties")
    public void testGetTokenEndpoint(Map<String, String> authenticatorProperties) {
        String tokenEndpoint = mailChimpAuthenticator.getTokenEndpoint(authenticatorProperties);
        Assert.assertEquals(MailChimpAuthenticatorConstants.MailChimp_TOKEN_ENDPOINT, tokenEndpoint);
    }

    @Test(description = "Test case for requiredIdToken method", dataProvider = "authenticatorProperties")
    public void testRequiredIdToken(Map<String, String> authenticatorProperties) {
        boolean isRequired = mailChimpAuthenticator.requiredIDToken(authenticatorProperties);
        Assert.assertFalse(isRequired);
    }

    @Test(description = "Test case for getFriendlyName method")
    public void testGetFriendlyName() {
        Assert.assertEquals(MailChimpAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME,
                mailChimpAuthenticator.getFriendlyName());
    }

    @Test(description = "Test case for getOauthResponse method")
    public void testGetOauthResponse() throws Exception {
        Mockito.when(mockOAuthClient.accessToken(mockOAuthClientRequest)).thenReturn(oAuthJSONAccessTokenResponse);
        OAuthClientResponse oAuthClientResponse = Whitebox
                .invokeMethod(mailChimpAuthenticator, "getOauthResponse", mockOAuthClient, mockOAuthClientRequest);
        Assert.assertNotNull(oAuthClientResponse);
    }

    @Test(description = "Test case for getAccessRequest method.")
    public void testGetAccessRequest() throws Exception {
        PowerMockito.mockStatic(OAuthClientRequest.class);
        Mockito.when(OAuthClientRequest.tokenLocation(Mockito.anyString()))
                .thenReturn(new OAuthClientRequest.TokenRequestBuilder("/token"));
        OAuthClientRequest accessRequest = Whitebox
                .invokeMethod(mailChimpAuthenticator, "getAccessRequest", "/token", "dummy-clientId", "dummy-code",
                        "dummy-secret", "/callback");
        Assert.assertNotNull(accessRequest);
        Assert.assertEquals(accessRequest.getLocationUri(), "/token");
    }

    @Test(description = "Test case for sendRequest method ", dataProvider = "authenticatorProperties")
    public void testSendRequest(Map<String, String> authenticateproperties) throws Exception {
        URL url = PowerMockito.mock(URL.class);
        PowerMockito.whenNew(URL.class).withArguments("http://test-url").thenReturn(url);
        MailChimpAuthenticator spyAuthenticator = PowerMockito.spy(new MailChimpAuthenticator());
        Mockito.when(oAuthClientResponse.getParam("access_token")).thenReturn("dummytoken");
        PowerMockito.doReturn("{\"id\":\"testuser\"}")
                .when(spyAuthenticator, "sendRequest", Mockito.anyString(), Mockito.anyString());
        Map<ClaimMapping, String> claims = mailChimpAuthenticator.getSubjectAttributes(oAuthClientResponse, authenticateproperties);
        Assert.assertEquals(0, claims.size());
    }

    @Test(description = "Test case for GetConfigurationProperties")
    public void testGetConfigurationProperties() {
        Assert.assertEquals(IdentityApplicationConstants.OAuth2.CALLBACK_URL,
                mailChimpAuthenticator.getConfigurationProperties().get(2).getName());
        Assert.assertEquals(4, mailChimpAuthenticator.getConfigurationProperties().size());
    }

    @Test(expectedExceptions = AuthenticationFailedException.class,
            description = "Negative Test case for processAuthenticationResponse",
            dataProvider = "authenticatorProperties")
    public void testProcessAuthenticationResponse(Map<String, String> authenticatorProperties) throws Exception {
        MailChimpAuthenticator spyAuthenticator = PowerMockito.spy(new MailChimpAuthenticator());
        PowerMockito.when(httpServletRequest.getParameter(anyString())).thenReturn("method");
        context.setAuthenticatorProperties(authenticatorProperties);
        PowerMockito.mockStatic(OAuthAuthzResponse.class);
        Mockito.when(OAuthAuthzResponse.oauthCodeAuthzResponse(Mockito.any(HttpServletRequest.class))).
                thenReturn(authAuthzResponse);
        PowerMockito.mockStatic(OAuthClientRequest.class);
        Mockito.when(OAuthClientRequest.tokenLocation(Mockito.anyString())).thenReturn(new OAuthClientRequest.
                TokenRequestBuilder("https://test-url"));
        PowerMockito.whenNew(OAuthClient.class).withAnyArguments().thenReturn(oAuthClient);
        Mockito.when(mockOAuthClient.accessToken(mockOAuthClientRequest)).thenReturn(oAuthJSONAccessTokenResponse);
        Mockito.when(oAuthClient.accessToken(Mockito.any(OAuthClientRequest.class))).
                thenReturn(oAuthJSONAccessTokenResponse);
        spyAuthenticator.processAuthenticationResponse(httpServletRequest, httpServletResponse, context);
    }
}
