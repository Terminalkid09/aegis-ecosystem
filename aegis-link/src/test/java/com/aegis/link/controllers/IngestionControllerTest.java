package com.aegis.link.controllers;

import com.aegis.link.dto.EventRequest;
import com.aegis.link.service.RedisService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(IngestionController.class)
class IngestionControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private RedisService redisService;

    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    @Test
    @WithMockUser
    void receiveEvent_Success() throws Exception {
        EventRequest request = EventRequest.builder()
                .agentId("test-agent")
                .pid(1234)
                .processName("test.exe")
                .os("Windows")
                .eventType("PROCESS_CREATED")
                .timestamp(Instant.now())
                .build();

        mockMvc.perform(post("/api/v1/events")
                        .with(csrf())
                        .header("X-Api-Key", "test-secret")
                        .header("X-Agent-Id", "test-agent")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.status").value("accepted"));

        verify(redisService).pushEvent(any(EventRequest.class));
    }

    @Test
    @WithMockUser
    void receiveEvent_AgentIdMismatch() throws Exception {
        EventRequest request = EventRequest.builder()
                .agentId("test-agent")
                .pid(1234)
                .processName("test.exe")
                .os("Windows")
                .eventType("PROCESS_CREATED")
                .timestamp(Instant.now())
                .build();

        mockMvc.perform(post("/api/v1/events")
                        .with(csrf())
                        .header("X-Api-Key", "test-secret")
                        .header("X-Agent-Id", "wrong-agent")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value("error"))
                .andExpect(jsonPath("$.message").value("X-Agent-Id header does not match agentId in body"));
    }

    @Test
    @WithMockUser
    void receiveEvent_ValidationError() throws Exception {
        EventRequest request = EventRequest.builder()
                // agentId missing
                .pid(-1) // invalid pid
                .processName("") // empty
                .os("Windows")
                .eventType("PROCESS_CREATED")
                .timestamp(Instant.now())
                .build();

        mockMvc.perform(post("/api/v1/events")
                        .with(csrf())
                        .header("X-Api-Key", "test-secret")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value("error"))
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("Validation failed")));
    }

    @Test
    @WithMockUser
    void health_Success() throws Exception {
        mockMvc.perform(get("/api/v1/health"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("aegis-link OK")));
    }
}
