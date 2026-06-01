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
        Object bootstrapObj = currentConfigs.get("bootstrap.servers");
        String bootstrap = null;
        if (bootstrapObj instanceof String) {
            bootstrap = (String) bootstrapObj;
        } else if (bootstrapObj instanceof java.util.List<?> list) {
            if (!list.isEmpty()) {
                bootstrap = String.valueOf(list.get(0));
            }
        }
        if (bootstrap != null && bootstrap.contains("aivencloud")) {
            log.info("Aiven Kafka bootstrap server detected: {}. Configuring SSL security...", bootstrap);
            try {
                // Đọc từ biến môi trường để bảo mật trên Cloud Render
                String ca = System.getenv("KAFKA_CA_PEM");
                String cert = System.getenv("KAFKA_SERVICE_CERT");
                String key = System.getenv("KAFKA_SERVICE_KEY");

                // Nếu không có biến môi trường (ví dụ chạy local), đọc dự phòng từ file trong resources
                if (ca == null || ca.isEmpty()) {
                    try { ca = readResource("ca.pem"); } catch (Exception ignored) {}
                }
                if (cert == null || cert.isEmpty()) {
                    try { cert = readResource("service.cert"); } catch (Exception ignored) {}
                }
                if (key == null || key.isEmpty()) {
                    try { key = readResource("service.key"); } catch (Exception ignored) {}
                }

                if (ca != null && cert != null && key != null) {
                    updates.put("security.protocol", "SSL");
                    updates.put("ssl.truststore.type", "PEM");
                    updates.put("ssl.truststore.certificates", ca);
                    updates.put("ssl.keystore.type", "PEM");
                    updates.put("ssl.keystore.key", key);
                    updates.put("ssl.keystore.certificate.chain", cert);
                    log.info("Kafka SSL configuration applied successfully.");
                } else {
                    log.warn("Kafka SSL certificates are missing from both environment variables and classpath resources.");
                }
            } catch (Exception e) {
                log.error("Failed to load Kafka SSL configurations", e);
            }
        }
    }

    private String readResource(String name) throws IOException {
        try (InputStream is = new ClassPathResource(name).getInputStream()) {
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
