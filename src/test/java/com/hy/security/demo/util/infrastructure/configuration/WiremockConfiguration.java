package com.hy.security.demo.util.infrastructure.configuration;

import com.github.tomakehurst.wiremock.common.ConsoleNotifier;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.extension.responsetemplating.ResponseTemplateTransformer;
import org.springframework.cloud.contract.wiremock.WireMockConfigurationCustomizer;
import org.springframework.context.annotation.Configuration;

@Configuration
public class WiremockConfiguration implements WireMockConfigurationCustomizer {

    @Override
    public void customize(WireMockConfiguration config) {
//        config.notifier(new ConsoleNotifier(true));
        config.extensions(new ResponseTemplateTransformer(false));
    }
}
