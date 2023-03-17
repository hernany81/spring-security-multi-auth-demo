package com.hy.security.demo.infrastructure.configuration;

import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@Import(UserDetailsServiceAutoConfiguration.class)
public class WebSecurityConfig {

    public static final String BASIC_AUTH_USER = "BASIC_AUTH_USER";

    @Bean
    SecurityFilterChain filterChain(
            HttpSecurity http,
            InMemoryUserDetailsManager userDetailsManager
    ) throws Exception {
        http
                .userDetailsService(userDetailsManager)
                .httpBasic()
                .and().oauth2Login().successHandler(
                        ((request, response, authentication) -> response.setStatus(HttpStatus.OK.value()))
                )
                .and().authorizeHttpRequests().anyRequest().authenticated();

        return http.build();
    }
}
