package com.aegis.link.service;

import com.aegis.link.dto.EventRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.Comparator;
import java.util.UUID;
import java.util.stream.Stream;

/**
 * Durable local spool for the overload path.
 *
 * Redis remains the hot path. When the bounded Redis queue is full (or Redis
 * is temporarily unreachable), Link writes the event to a local file before
 * returning success. A scheduled drain pushes files back to Redis and deletes
 * each file only after the push. A crash between push and delete produces a
 * duplicate, not a loss: this is at-least-once, not exactly-once.
 */
@Service
public class EventSpoolService {

    private static final Logger log = LoggerFactory.getLogger(EventSpoolService.class);

    private final RedisService redisService;
    private final ObjectMapper objectMapper;
    private final Path directory;
    private final boolean enabled;
    private final int maxFiles;
    private final int drainBatch;

    public EventSpoolService(
            RedisService redisService,
            ObjectMapper objectMapper,
            @Value("${aegis.link.spool.dir:${java.io.tmpdir}/aegis-link-spool}") String directory,
            @Value("${aegis.link.spool.enabled:true}") boolean enabled,
            @Value("${aegis.link.spool.max-files:100000}") int maxFiles,
            @Value("${aegis.link.spool.drain-batch:500}") int drainBatch) {
        this.redisService = redisService;
        this.objectMapper = objectMapper;
        this.directory = Path.of(directory);
        this.enabled = enabled;
        this.maxFiles = Math.max(1, maxFiles);
        this.drainBatch = Math.max(1, drainBatch);
    }

    public boolean isEnabled() {
        return enabled;
    }

    public Path directory() {
        return directory;
    }

    /** Persist the event before returning success to the sender. */
    public synchronized boolean spool(EventRequest event) {
        if (!enabled) return false;
        try {
            Files.createDirectories(directory);
            if (countFiles() >= maxFiles) {
                log.error("Spool full ({} files), refusing event from agent={}",
                        maxFiles, event.getAgentId());
                return false;
            }
            String json = objectMapper.writeValueAsString(event);
            String name = "%019d-%s.json".formatted(System.currentTimeMillis(), UUID.randomUUID());
            Path temporary = directory.resolve(name + ".tmp");
            Files.writeString(temporary, json, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            Files.move(temporary, directory.resolve(name),
                    StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            log.warn("Event spooled locally: agent={} file={}", event.getAgentId(), name);
            return true;
        } catch (Exception exc) {
            log.error("Durable spool write failed for agent={}: {}", event.getAgentId(), exc.getMessage());
            return false;
        }
    }

    /** Push spooled files in order; a failed push stops the batch for retry. */
    @Scheduled(fixedDelayString = "${aegis.link.spool.drain-ms:2000}")
    public synchronized void drain() {
        if (!enabled || !Files.isDirectory(directory)) return;
        int pushed = 0;
        try (Stream<Path> files = Files.list(directory)) {
            for (Path file : files
                    .filter(path -> path.getFileName().toString().endsWith(".json"))
                    .sorted(Comparator.comparing(path -> path.getFileName().toString()))
                    .limit(drainBatch)
                    .toList()) {
                EventRequest event;
                try {
                    String json = Files.readString(file, StandardCharsets.UTF_8);
                    event = objectMapper.readValue(json, EventRequest.class);
                } catch (Exception corrupt) {
                    // A malformed file must not block every later event. Keep
                    // it for inspection under a non-drained suffix and move on.
                    log.error("Spool file {} is corrupt: {}", file.getFileName(), corrupt.getMessage());
                    try {
                        Files.move(file, file.resolveSibling(file.getFileName() + ".bad"),
                                StandardCopyOption.REPLACE_EXISTING);
                    } catch (IOException moveError) {
                        log.error("Could not quarantine spool file {}: {}", file.getFileName(), moveError.getMessage());
                    }
                    continue;
                }
                try {
                    if (!redisService.pushEventIfRoom(event)) {
                        // Redis is reachable but at its cap. Keep the file and
                        // retry on the next drain instead of growing Redis.
                        log.warn("Spool drain paused at {}: Redis queue full", file.getFileName());
                        break;
                    }
                    Files.deleteIfExists(file);
                    pushed++;
                } catch (Exception exc) {
                    log.warn("Spool drain paused at {}: {}", file.getFileName(), exc.getMessage());
                    break;
                }
            }
        } catch (IOException exc) {
            log.error("Spool drain failed: {}", exc.getMessage());
        }
        if (pushed > 0) log.info("Spool drained {} event(s) to Redis", pushed);
    }

    private long countFiles() throws IOException {
        try (Stream<Path> files = Files.list(directory)) {
            return files.filter(path -> path.getFileName().toString().endsWith(".json")).count();
        }
    }
}
