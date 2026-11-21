package com.aegis.link.config;

import com.aegis.link.dto.EventRequest;
import com.aegis.link.service.EventSpoolService;
import com.aegis.link.service.RedisService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.integration.dsl.IntegrationFlow;
import org.springframework.messaging.Message;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static org.springframework.integration.ip.dsl.Udp.inboundAdapter;

@Configuration
public class SyslogConfig {

    private static final Logger log = LoggerFactory.getLogger(SyslogConfig.class);
    private static final int SYSLOG_PORT = 1514;

    private final RedisService redisService;
    private final EventSpoolService spoolService;

    public SyslogConfig(RedisService redisService, EventSpoolService spoolService) {
        this.redisService = redisService;
        this.spoolService = spoolService;
    }

    @Bean
    public IntegrationFlow syslogFlow() {
        log.info("Syslog receiver configured to listen on UDP port {}", SYSLOG_PORT);
        return IntegrationFlow.from(inboundAdapter(SYSLOG_PORT))
                .handle(this::handleSyslogMessage)
                .get();
    }

    private void handleSyslogMessage(Message<?> message) {
        try {
            Object payload = message.getPayload();
            String msg;
            if (payload instanceof byte[] bytes) {
                msg = new String(bytes, StandardCharsets.UTF_8);
            } else if (payload instanceof String text) {
                msg = text;
            } else {
                msg = String.valueOf(payload);
            }

            String host = message.getHeaders().get("ip_address", String.class);
            if (host == null) {
                host = "unknown";
            }

            EventRequest event = EventRequest.builder()
                    .agentId("network-device-" + host)
                    .timestamp(Instant.now())
                    .eventType("SYSLOG_NETWORK")
                    .hostname(host)
                    .os("Network/Appliance")
                    .processName("syslog")
                    .processPath("udp")
                    .fileHash(msg)
                    .build();

            try {
                redisService.pushEvent(event);
            } catch (RuntimeException redisError) {
                if (!spoolService.spool(event)) throw redisError;
                log.warn("Syslog event spooled locally after Redis failure from {}", host);
            }
            log.debug("Processed syslog message from {}: {}", host, msg);
        } catch (Exception e) {
            log.error("Error processing syslog message", e);
        }
    }
}
