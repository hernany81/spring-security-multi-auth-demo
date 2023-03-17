package com.hy.security.demo.infrastructure.configuration;

import com.hy.security.demo.application.rest.dto.Message;
import com.hy.security.demo.domain.service.MessageService;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatusCode;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;

import static com.hy.security.demo.infrastructure.configuration.WebSecurityConfig.BASIC_AUTH_USER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.when;

/**
 * Component test to check basic auth flow and spring security configuration
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
public class BasicAuthTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @MockBean
    private InMemoryUserDetailsManager userDetailsManager;

    @MockBean
    private MessageService messageService;

    @MockBean
    private PasswordEncoder passwordEncoder;

    @Test
    public void cannotAccessMessagesEndpointWithBadCredentials() {
        // Arrange
        var username = "john.doe@mail.com";
        var password = "secret";

        when(
                userDetailsManager.loadUserByUsername(anyString())
        ).thenThrow(new UsernameNotFoundException("User not found"));

        // Act
        var req = buildHttpEntityWithBasicAuth(username, password);
        var response = restTemplate.exchange("/api/messages", HttpMethod.GET, req, new ParameterizedTypeReference<List<Message>>() {
        });

        // Assert
        assertThat(response.getStatusCode()).isEqualTo(HttpStatusCode.valueOf(HttpStatus.SC_UNAUTHORIZED));
        Mockito.verify(messageService, never()).getMessagesByUserName(anyString());
    }

    @Test
    public void canAccessMessagesEndpointWithValidCredentials() {
        // Arrange
        var username = "john.doe@mail.com";
        var password = "secret";

        when(
                userDetailsManager.loadUserByUsername(anyString())
        ).thenReturn(
                User
                        .withUsername(username)
                        .password(password)
                        .authorities(BASIC_AUTH_USER)
                        .build()
        );

        arrangePasswordEncoder();

        // Act
        var req = buildHttpEntityWithBasicAuth(username, password);
        var response = restTemplate.exchange("/api/messages", HttpMethod.GET, req, new ParameterizedTypeReference<List<Message>>() {
        });

        // Assert
        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        Mockito.verify(messageService).getMessagesByUserName(anyString());
    }

    @Test
    public void canAccessInternalUsersMessagesEndpointWithValidCredentials() {
        // Arrange
        var username = "john.doe@mail.com";
        var password = "secret";

        when(
                userDetailsManager.loadUserByUsername(anyString())
        ).thenReturn(
                User
                        .withUsername(username)
                        .password(password)
                        .authorities(BASIC_AUTH_USER)
                        .build()
        );

        arrangePasswordEncoder();

        // Act
        var req = buildHttpEntityWithBasicAuth(username, password);
        var response = restTemplate.exchange("/api/internal-users-messages", HttpMethod.GET, req, new ParameterizedTypeReference<List<Message>>() {
        });

        // Assert
        assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
        Mockito.verify(messageService).getMessagesForInternalUsers();
    }

    @Test
    public void cannotAccessSsoUsersMessagesEndpointWithValidCredentials() {
        // Arrange
        var username = "john.doe@mail.com";
        var password = "secret";

        when(
                userDetailsManager.loadUserByUsername(anyString())
        ).thenReturn(
                User
                        .withUsername(username)
                        .password(password)
                        .authorities(BASIC_AUTH_USER)
                        .build()
        );

        arrangePasswordEncoder();

        // Act
        var req = buildHttpEntityWithBasicAuth(username, password);
        var response = restTemplate.exchange("/api/sso-users-messages", HttpMethod.GET, req, String.class);

        // Assert
        assertThat(response.getStatusCode()).isEqualTo(HttpStatusCode.valueOf(HttpStatus.SC_FORBIDDEN));
        Mockito.verify(messageService, never()).getMessagesForSsoUsers();
    }

    private void arrangePasswordEncoder() {
        when(passwordEncoder.encode(anyString())).then(a -> a.getArgument(0));
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(true);
    }

    private <T> HttpEntity<T> buildHttpEntityWithBasicAuth(String username, String password) {
        var reqHeaders = new org.springframework.http.HttpHeaders();
        reqHeaders.setBasicAuth(username, password);
        return new HttpEntity<>(null, reqHeaders);
    }
}
