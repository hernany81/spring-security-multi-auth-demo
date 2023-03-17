package com.hy.security.demo.infrastructure.configuration;

import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebResponse;
import com.gargoylesoftware.htmlunit.html.HtmlAnchor;
import com.gargoylesoftware.htmlunit.html.HtmlInput;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlSubmitInput;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.extension.responsetemplating.ResponseTemplateTransformer;
import com.hy.security.demo.domain.service.MessageService;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.cloud.contract.wiremock.AutoConfigureWireMock;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatusCode;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.util.MimeTypeUtils;

import java.io.IOException;
import java.time.Clock;
import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.when;

/**
 * Component test to check oAuth2 "authorization_code" flow and spring security configuration
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles({"test", "wiremock"})
@AutoConfigureWireMock(port = 0)
public class OAuth2Test {

    private static final String OAUTH2_PROVIDER_AUTHORIZE_ENDPOINT = "/oauth2/authorize";
    private static final String OAUTH2_PROVIDER_LOGIN_ENDPOINT = "/login";
    private static final String OAUTH2_PROVIDER_TOKEN_ENDPOINT = "/oauth2/token";

    private final WebClient webClient = new WebClient();

    @Autowired
    private TestRestTemplate restTemplate;

    @LocalServerPort
    private int localServerPort;

    @Value("${wiremock.server.port}")
    private int wireMockPort;

    @MockBean
    private JwtDecoderFactory<ClientRegistration> jwtDecoderFactory;

    @Mock
    private JwtDecoder jwtDecoder;

    @MockBean
    private MessageService messageService;

    @BeforeEach
    public void setUp() {
        this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
        this.webClient.getOptions().setRedirectEnabled(true);
        this.webClient.getCookieManager().clearCookies();    // log out
    }

    @AfterEach
    public void afterAll() {
        this.webClient.close();
    }

    @Test
    public void givenUnauthenticatedUserWhenAccessingProtectedEndpointThenRedirectedToLoginScreen() throws Exception {
        // Arrange
        arrangeOAuth2ProviderAuthorizeEndpoint();

        // Act
        HtmlPage loginScreen = this.webClient.getPage(getLocalUrl("/api/messages"));

        // Assert
        assertOAuthProviderLoginPage(loginScreen);
        // OAuth provider endpoints where invoked
        verify(1, anyRequestedFor(urlPathEqualTo(OAUTH2_PROVIDER_AUTHORIZE_ENDPOINT)));
    }

    private static List<Arguments> getLogInWithOAuth2ProviderParameters() {
        return List.of(
                Arguments.of("Successful oAuth sign in", true, HttpStatus.SC_OK),
                Arguments.of("Failed oAuth sign in", false, HttpStatus.SC_BAD_REQUEST)
        );
    }

    @ParameterizedTest(name = "log in with OAuth provider - [{index}] {argumentsWithNames}")
    @MethodSource("getLogInWithOAuth2ProviderParameters")
    public void logInWithOAuth2Provider(String testName, Boolean successLogin, int expectedStatusCode) throws Exception {
        // Arrange
        var username = "john.doe@mail.com";
        arrangeOAuth2ProviderEndpoints(successLogin);

        // Act
        // Go to login page
        HtmlPage localLoginPage = this.webClient.getPage(getLocalUrl("/login"));
        assertLocalLoginPage(localLoginPage);
        HtmlPage oAuthLoginPage = goToOAuthLoginPage(localLoginPage);
        var nonce = getNonceFromOAuthLoginPage(oAuthLoginPage);

        // need to mock returned JWT with user info at this point as we need the generated "nonce"
        arrangeReturnedJwt(nonce, username);

        // From the login page (current app) log in through the OAuth provider login page
        var oAuthLoginResponse = loginWithOAuthProvider(oAuthLoginPage, username, "secret");

        // Assert
        // OAuth login result
        assertThat(oAuthLoginResponse.getStatusCode()).isEqualTo(expectedStatusCode);

        // OAuth provider endpoints where invoked
        verify(1, anyRequestedFor(urlPathEqualTo(OAUTH2_PROVIDER_AUTHORIZE_ENDPOINT)));
        verify(1, anyRequestedFor(urlPathEqualTo(OAUTH2_PROVIDER_LOGIN_ENDPOINT)));
        verify(successLogin ? 1 : 0, anyRequestedFor(urlPathEqualTo(OAUTH2_PROVIDER_TOKEN_ENDPOINT)));
    }

    @Test
    public void loggedInUserCanAccessMessagesEndpoint() throws Exception {
        // Arrange
        var username = "john.doe@mail.com";
        var oAuthLoginResponse = performUserLogIn(username);

        when(
                messageService.getMessagesByUserName(anyString())
        ).thenReturn(
                List.of()
        );

        // Act
        var req = buildHttpEntityWithCookie(oAuthLoginResponse);
        var response = restTemplate.exchange("/api/messages", HttpMethod.GET, req, new ParameterizedTypeReference<List<com.hy.security.demo.application.rest.dto.Message>>() {
        });

        // Assert
        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).isEmpty();
        Mockito.verify(messageService).getMessagesByUserName(anyString());
    }

    @Test
    public void loggedInUserCanAccessSsoUsersMessagesEndpoint() throws Exception {
        // Arrange
        var username = "john.doe@mail.com";
        var oAuthLoginResponse = performUserLogIn(username);

        when(
                messageService.getMessagesForSsoUsers()
        ).thenReturn(
                List.of()
        );

        // Act
        var req = buildHttpEntityWithCookie(oAuthLoginResponse);
        var response = restTemplate.exchange("/api/sso-users-messages", HttpMethod.GET, req, new ParameterizedTypeReference<List<com.hy.security.demo.application.rest.dto.Message>>() {
        });

        // Assert
        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        assertThat(response.getBody()).isEmpty();
        Mockito.verify(messageService).getMessagesForSsoUsers();
    }

    @Test
    public void loggedInUserCannotAccessInternalUsersMessagesEndpoint() throws Exception {
        // Arrange
        var username = "john.doe@mail.com";
        var oAuthLoginResponse = performUserLogIn(username);

        // Act
        var req = buildHttpEntityWithCookie(oAuthLoginResponse);
        var response = restTemplate.exchange("/api/internal-users-messages", HttpMethod.GET, req, String.class);

        // Assert
        assertThat(response.getStatusCode()).isEqualTo(HttpStatusCode.valueOf(HttpStatus.SC_FORBIDDEN));
        Mockito.verify(messageService, never()).getMessagesForInternalUsers();
    }

    private String getLocalUrl(String path) {
        return "http://localhost:%s%s".formatted(localServerPort, path);
    }

    private void arrangeOAuth2ProviderAuthorizeEndpoint() {
        // Stub for OAuth provider "authorize" endpoint
        stubFor(
                WireMock
                        .get(urlPathEqualTo(OAUTH2_PROVIDER_AUTHORIZE_ENDPOINT))
                        .willReturn(
                                aResponse()
                                        .withStatus(HttpStatus.SC_OK)
                                        .withHeader(HttpHeaders.CONTENT_TYPE, MimeTypeUtils.TEXT_HTML_VALUE)
                                        .withBodyFile("oauth-provider/login.html")
                                        .withTransformers(ResponseTemplateTransformer.NAME)
                        )
        );
    }

    private void arrangeOAuth2ProviderLoginEndpoint(Boolean successLogin) {
        // Stub for OAuth provider "login" endpoint
        var loginResponseDefinitionBuilder = successLogin
                ? temporaryRedirect("{{formData request.body 'form' urlDecode=true}}{{{form.redirectUri}}}?code={{{randomValue length=30 type='ALPHANUMERIC'}}}&state={{{form.state}}}")
                : status(HttpStatus.SC_BAD_REQUEST);

        stubFor(
                WireMock
                        .post(urlPathEqualTo(OAUTH2_PROVIDER_LOGIN_ENDPOINT))
                        .willReturn(
                                loginResponseDefinitionBuilder
                                        .withTransformers(ResponseTemplateTransformer.NAME)
                        )
        );
    }

    private void arrangeOAuth2ProviderTokenEndpoint() {
        // Stub for OAuth provider "token" endpoint
        stubFor(
                WireMock
                        .post(urlPathEqualTo(OAUTH2_PROVIDER_TOKEN_ENDPOINT))
                        .willReturn(
                                okJson("""
                                            {
                                                "token_type": "Bearer",
                                                "access_token": "{{randomValue length=20 type='ALPHANUMERIC'}}",
                                                "id_token": "fake_jwt_token"
                                            }
                                        """).withTransformers(ResponseTemplateTransformer.NAME)
                        )
        );
    }

    private void arrangeOAuth2ProviderEndpoints(Boolean successLogin) {
        arrangeOAuth2ProviderAuthorizeEndpoint();
        arrangeOAuth2ProviderLoginEndpoint(successLogin);
        arrangeOAuth2ProviderTokenEndpoint();
    }

    private void arrangeReturnedJwt(String nonce, String username) {
        var tokenVal = "fake_jwt_token";
        var now = Clock.systemUTC().instant();
        var expiration = now.plusSeconds(60 * 10);

        // Mock for JwtDecoderFactory as we want to avoid the JWT complexity when deserializing the id_token from OIDC
        when(
                jwtDecoderFactory.createDecoder(ArgumentMatchers.any(ClientRegistration.class))
        ).thenReturn(jwtDecoder);

        when(jwtDecoder.decode(tokenVal))
                .thenReturn(
                        Jwt
                                .withTokenValue(tokenVal)
                                .header("val", "demo")  // need at least one header
                                .claim(IdTokenClaimNames.SUB, username)
                                .claim(IdTokenClaimNames.AZP, "messaging-client")
                                .claim(IdTokenClaimNames.ISS, "http://localhost:%s".formatted(wireMockPort))
                                .claim(IdTokenClaimNames.IAT, now)
                                .claim(IdTokenClaimNames.EXP, expiration)
                                .claim(IdTokenClaimNames.NONCE, nonce)
                                .issuedAt(now)
                                .expiresAt(expiration)
                                .build()
                );
    }

    private void assertLocalLoginPage(HtmlPage page) {
        assertThat(page.getUrl().toString()).endsWith("/login");
        var signInHeader = page.querySelector(".form-signin-heading");

        assertThat(signInHeader.getTextContent()).contains("Login with OAuth 2.0");
    }

    private void assertOAuthProviderLoginPage(HtmlPage page) {
        var documentTitle = page.querySelector("title");

        assertThat(documentTitle.getTextContent()).contains("Welcome to the OAuth provider login page!");
    }

    private HtmlPage goToOAuthLoginPage(HtmlPage localLoginPage) throws IOException {
        HtmlAnchor loginLink = localLoginPage.querySelector("a");
        return loginLink.click();
    }

    private String getNonceFromOAuthLoginPage(HtmlPage page) {
        HtmlInput nonceInput = page.querySelector("input[name=nonce]");
        var nonce = nonceInput.getValue();

        assertThat(nonce).isNotEmpty();
        return nonce;
    }

    /**
     * @return http response status code
     */
    private WebResponse loginWithOAuthProvider(HtmlPage oAuthLoginPage, String username, String password) throws Exception {
        HtmlInput usernameInput = oAuthLoginPage.querySelector("input[name=username]");
        usernameInput.setValue(username);

        HtmlInput passwordInput = oAuthLoginPage.querySelector("input[name=password]");
        passwordInput.setValue(password);

        HtmlSubmitInput submitInput = oAuthLoginPage.querySelector("input[type=submit]");
        var newPage = submitInput.click();

        return newPage.getWebResponse();
    }

    private WebResponse performUserLogIn(String username) throws Exception {
        arrangeOAuth2ProviderEndpoints(true);

        // Go to login page
        HtmlPage localLoginPage = this.webClient.getPage(getLocalUrl("/login"));
        HtmlPage oAuthLoginPage = goToOAuthLoginPage(localLoginPage);
        var nonce = getNonceFromOAuthLoginPage(oAuthLoginPage);

        // need to mock returned JWT with user info at this point as we need the generated "nonce"
        arrangeReturnedJwt(nonce, username);

        // From the login page (current app) log in through the OAuth provider login page
        var oAuthLoginResponse = loginWithOAuthProvider(oAuthLoginPage, username, "secret");

        assertThat(oAuthLoginResponse.getStatusCode()).isEqualTo(HttpStatus.SC_OK);

        return oAuthLoginResponse;
    }

    private <T> HttpEntity<T> buildHttpEntityWithCookie(WebResponse oAuthLoginResponse) {
        var reqHeaders = new org.springframework.http.HttpHeaders();
        reqHeaders.set(
                org.springframework.http.HttpHeaders.COOKIE,
                oAuthLoginResponse.getResponseHeaderValue(org.springframework.http.HttpHeaders.SET_COOKIE)
        );
        return new HttpEntity<>(null, reqHeaders);
    }

}
