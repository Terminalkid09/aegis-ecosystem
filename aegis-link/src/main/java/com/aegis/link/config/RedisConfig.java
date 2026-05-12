package com.aegis.link.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

/*
Configurazione del client Redis.

Due scelte importanti:

1. Serializzatore chiavi → StringRedisSerializer
Le chiavi Redis sono stringhe semplici (es. "aegis:events").
Usando StringRedisSerializer evitiamo prefissi binari indesiderati.

2. Serializzatore valori → GenericJackson2JsonRedisSerializer
Gli eventi vengono salvati come JSON leggibile.
Il JavaTimeModule è necessario per serializzare java.time.Instant
(usato nel campo timestamp di EventRequest) in formato ISO-8601.

Senza questa configurazione Spring userebbe la serializzazione Java
binaria di default, rendendo i dati illeggibili da aegis-brain (Python).
*/
@Configuration
public class RedisConfig {

    @Bean
    public ObjectMapper redisObjectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        // Abilita la gestione dei tipi java.time (Instant, LocalDate, ecc.)
        mapper.registerModule(new JavaTimeModule());
        // Salva Instant come stringa ISO-8601 invece di un array [year, month, ...]
        mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        return mapper;
    }

    @Bean
    public RedisTemplate<String, Object> redisTemplate(
            RedisConnectionFactory connectionFactory,
            ObjectMapper redisObjectMapper) {

        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);

        // Chiavi come stringhe pure
        StringRedisSerializer stringSerializer = new StringRedisSerializer();
        template.setKeySerializer(stringSerializer);
        template.setHashKeySerializer(stringSerializer);

        // Valori come JSON — usa il mapper con JavaTimeModule
        GenericJackson2JsonRedisSerializer jsonSerializer =
                new GenericJackson2JsonRedisSerializer(redisObjectMapper);
        template.setValueSerializer(jsonSerializer);
        template.setHashValueSerializer(jsonSerializer);

        template.afterPropertiesSet();
        return template;
    }
}
