package com.aegis.link.controllers;

import com.aegis.link.dto.EventRequest;
import com.aegis.link.service.CommandDeliveryService;
import com.aegis.link.service.EventSpoolService;
import com.aegis.link.service.RedisService;
import tools.jackson.databind.cfg.DateTimeFeature;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(IngestionController.class)
class IngestionControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private RedisService redisService;

    @MockitoBean
    private EventSpoolService spoolService;

    @MockitoBean
    private CommandDeliveryService commandDeliveryService;

    private JsonMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = JsonMapper.builder()
                .disable(DateTimeFeature.WRITE_DATES_AS_TIMESTAMPS)
                .build();
    }

    @Test
    @WithMockUser
    void receiveEvent_Success() throws Exception {
        org.mockito.Mockito.when(redisService.getAgentIdBySecret("test-secret"))
                .thenReturn("test-agent");
        org.mockito.Mockito.when(redisService.pushEventIfRoom(any(EventRequest.class), eq(RedisService.MAX_QUEUE_SIZE)))
                .thenReturn(true);
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

        verify(redisService).pushEventIfRoom(any(EventRequest.class), eq(RedisService.MAX_QUEUE_SIZE));
    }

    @Test
    @WithMockUser
    void receiveEvent_AgentIdMismatch() throws Exception {
        org.mockito.Mockito.when(redisService.getAgentIdBySecret("test-secret"))
                .thenReturn("test-agent");
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
        org.mockito.Mockito.when(redisService.getAgentIdBySecret("test-secret"))
                .thenReturn("test-agent");
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
                        .header("X-Agent-Id", "test-agent")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value("error"))
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("Validation failed")));
    }

    @Test
    @WithMockUser
    void getCommands_ReturnsClaimedPayload() throws Exception {
        org.mockito.Mockito.when(redisService.getAgentIdBySecret("test-secret"))
                .thenReturn("test-agent");
        org.mockito.Mockito.when(commandDeliveryService.claim("test-agent"))
                .thenReturn("{\"command\":\"GET_TELEMETRY\",\"delivery_id\":\"d-1\"}");

        mockMvc.perform(get("/api/v1/commands")
                        .header("X-Api-Key", "test-secret")
                        .header("X-Agent-Id", "test-agent"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("delivery_id")));

        verify(commandDeliveryService).claim("test-agent");
    }

    @Test
    @WithMockUser
    void ackCommand_IsIdempotentAndAuthorized() throws Exception {
        org.mockito.Mockito.when(redisService.getAgentIdBySecret("test-secret"))
                .thenReturn("test-agent");
        org.mockito.Mockito.when(commandDeliveryService.ack("test-agent", "d-1"))
                .thenReturn(true);

        mockMvc.perform(post("/api/v1/telemetry/commands/ack")
                        .with(csrf())
                        .header("X-Api-Key", "test-secret")
                        .header("X-Agent-Id", "test-agent")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"delivery_id\":\"d-1\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("acked"))
                .andExpect(jsonPath("$.duplicate").value(false));

        verify(commandDeliveryService).ack("test-agent", "d-1");
    }

    @Test
    @WithMockUser
    void health_Success() throws Exception {
        mockMvc.perform(get("/api/v1/health"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("aegis-link OK")));
    }

    @Test
    @WithMockUser
    void receiveEvent_QueueFullReturns429() throws Exception {
        org.mockito.Mockito.when(redisService.getAgentIdBySecret("test-secret"))
                .thenReturn("test-agent");
        org.mockito.Mockito.when(redisService.pushEventIfRoom(any(EventRequest.class), eq(RedisService.MAX_QUEUE_SIZE)))
                .thenReturn(false);
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
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", "5"))
                .andExpect(jsonPath("$.message").value("Ingestion queue full and spool unavailable, retry later"));
    }

    @Test
    @WithMockUser
    void receiveEvent_QueueFullIsSpooledDurably() throws Exception {
        org.mockito.Mockito.when(redisService.getAgentIdBySecret("test-secret"))
                .thenReturn("test-agent");
        org.mockito.Mockito.when(redisService.pushEventIfRoom(any(EventRequest.class), eq(RedisService.MAX_QUEUE_SIZE)))
                .thenReturn(false);
        org.mockito.Mockito.when(spoolService.spool(any(EventRequest.class))).thenReturn(true);
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
                .andExpect(jsonPath("$.status").value("spooled"));

        verify(spoolService).spool(any(EventRequest.class));
        verify(redisService, org.mockito.Mockito.never()).pushEvent(any());
    }

    @Test
    @WithMockUser
    void receiveEvent_RedisDownIsSpooledInsteadOfReturning500() throws Exception {
        org.mockito.Mockito.when(redisService.getAgentIdBySecret("test-secret"))
                .thenReturn("test-agent");
        org.mockito.Mockito.when(redisService.pushEventIfRoom(any(EventRequest.class), eq(RedisService.MAX_QUEUE_SIZE)))
                .thenThrow(new RuntimeException("Redis unavailable"));
        org.mockito.Mockito.when(spoolService.spool(any(EventRequest.class))).thenReturn(true);
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
                .andExpect(jsonPath("$.status").value("spooled"));

        verify(spoolService).spool(any(EventRequest.class));
    }

    @Test
    @WithMockUser
    void receiveEvent_RedisDownAndSpoolDownReturns503NotAccepted() throws Exception {
        org.mockito.Mockito.when(redisService.getAgentIdBySecret("test-secret"))
                .thenReturn("test-agent");
        org.mockito.Mockito.when(redisService.pushEventIfRoom(any(EventRequest.class), eq(RedisService.MAX_QUEUE_SIZE)))
                .thenThrow(new RuntimeException("Redis unavailable"));
        org.mockito.Mockito.when(spoolService.spool(any(EventRequest.class))).thenReturn(false);
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
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.status").value("error"));
    }
}
