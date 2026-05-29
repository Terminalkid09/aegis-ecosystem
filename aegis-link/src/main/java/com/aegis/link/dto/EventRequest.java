package com.aegis.link.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EventRequest {

    @NotBlank(message = "agentId is required")
    private String agentId;

    @NotNull(message = "timestamp is required")
    private Instant timestamp;

    @NotBlank(message = "eventType is required")
    private String eventType;

    // System Info
    private String hostname;
    private String ipAddress;
    private String os;

    // Process Info (for events)
    private long pid;
    private String processName;
    private String processPath;
    private String user;
    private String fileHash;

    // Metrics Info (for telemetry)
    private Double cpuUsage;
    private Double ramUsage;
    private Long diskFree;
    private Long diskTotal;
    private Long networkSent;
    private Long networkReceived;
    private List<Map<String, Object>> processes;
}
