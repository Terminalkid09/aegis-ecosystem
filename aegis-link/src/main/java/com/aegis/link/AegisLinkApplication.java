package com.aegis.link;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/*
Entry point di aegis-link.
 *
Responsabilità:
- Riceve gli eventi di sistema dagli agenti aegis-guard via HTTP
- Valida il payload in ingresso
- Mette in coda gli eventi su Redis per aegis-brain

Flusso:
aegis-guard → POST /api/v1/events → IngestionController
            → RedisService → LPUSH aegis:events
            → aegis-brain (BRPOP consumer)
 */
@SpringBootApplication
public class AegisLinkApplication {
    public static void main(String[] args) {
        SpringApplication.run(AegisLinkApplication.class, args);
    }
}
