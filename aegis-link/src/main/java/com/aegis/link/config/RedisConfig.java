package com.aegis.link.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJacksonJsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import tools.jackson.databind.cfg.DateTimeFeature;
import tools.jackson.databind.json.JsonMapper;

/*
Configurazione del client Redis.

Due scelte importanti:

1. Serializzatore chiavi → StringRedisSerializer
Le chiavi Redis sono stringhe semplici (es. "aegis:events").
Usando StringRedisSerializer evitiamo prefissi binari indesiderati.

2. Serializzatore valori → GenericJacksonJsonRedisSerializer
Gli eventi vengono salvati come JSON leggibile.
Il JavaTimeModule è necessario per serializzare java.time.Instant
(usato nel campo timestamp di EventRequest) in formato ISO-8601.

Senza questa configurazione Spring userebbe la serializzazione Java
binaria di default, rendendo i dati illeggibili da aegis-brain (Python).
*/
@Configuration
public class RedisConfig {

    @Bean
    public RedisTemplate<String, Object> redisTemplate(
            RedisConnectionFactory connectionFactory) {

        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);

        // Chiavi come stringhe pure
        StringRedisSerializer stringSerializer = new StringRedisSerializer();
        template.setKeySerializer(stringSerializer);
        template.setHashKeySerializer(stringSerializer);

        // Jackson 3 include il supporto java.time nel databind: niente
        // jackson-datatype-jsr310 separato. Il mapper resta locale al template
        // per non sostituire il JsonMapper auto-configurato da Spring Boot.
        JsonMapper jsonMapper = JsonMapper.builder()
                // Salva Instant come stringa ISO-8601 invece di un array
                .disable(DateTimeFeature.WRITE_DATES_AS_TIMESTAMPS)
                .build();
        GenericJacksonJsonRedisSerializer jsonSerializer =
                new GenericJacksonJsonRedisSerializer(jsonMapper);
        template.setValueSerializer(jsonSerializer);
        template.setHashValueSerializer(jsonSerializer);

        template.afterPropertiesSet();
        return template;
    }
}
