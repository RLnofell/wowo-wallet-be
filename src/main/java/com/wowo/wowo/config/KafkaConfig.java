/*
 * ******************************************************
 *  * Copyright (c) 2024 htilssu
 *  *
 *  * This code is the property of htilssu. All rights reserved.
 *  * Redistribution or reproduction of any part of this code
 *  * in any form, with or without modification, is strictly
 *  * prohibited without prior written permission from the author.
 *  *
 *  * Author: htilssu
 *  * Created: 14-11-2024
 *  ******************************************************
 */

package com.wowo.wowo.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.kafka.DefaultKafkaConsumerFactoryCustomizer;
import org.springframework.boot.autoconfigure.kafka.DefaultKafkaProducerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@Configuration
public class KafkaConfig {

    @Bean
    public DefaultKafkaProducerFactoryCustomizer producerFactoryCustomizer() {
        return producerFactory -> {
            Map<String, Object> updates = new HashMap<>();
            addSslConfigs(producerFactory.getConfigurationProperties(), updates);
            producerFactory.updateConfigs(updates);
        };
    }

    @Bean
    public DefaultKafkaConsumerFactoryCustomizer consumerFactoryCustomizer() {
        return consumerFactory -> {
            Map<String, Object> updates = new HashMap<>();
            addSslConfigs(consumerFactory.getConfigurationProperties(), updates);
            consumerFactory.updateConfigs(updates);
        };
    }

    private void addSslConfigs(Map<String, Object> currentConfigs, Map<String, Object> updates) {
        String bootstrap = (String) currentConfigs.get("bootstrap.servers");
        if (bootstrap != null && bootstrap.contains("aivencloud")) {
            log.info("Aiven Kafka bootstrap server detected: {}. Configuring SSL using classpath PEM files...", bootstrap);
            try {
                String ca = readResource("ca.pem");
                String cert = readResource("service.cert");
                String key = readResource("service.key");

                updates.put("security.protocol", "SSL");
                updates.put("ssl.truststore.type", "PEM");
                updates.put("ssl.truststore.certificates", ca);
                updates.put("ssl.keystore.type", "PEM");
                updates.put("ssl.keystore.key", key);
                updates.put("ssl.keystore.certificate.chain", cert);
                log.info("Kafka SSL configuration applied successfully.");
            } catch (Exception e) {
                log.error("Failed to load Kafka SSL certificates from classpath resources (ca.pem, service.cert, service.key)", e);
            }
        }
    }

    private String readResource(String name) throws IOException {
        try (InputStream is = new ClassPathResource(name).getInputStream()) {
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
