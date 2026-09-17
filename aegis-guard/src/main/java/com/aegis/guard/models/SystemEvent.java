package com.aegis.guard.models;

import java.time.Instant;

/*
Rappresenta un evento di sistema rilevato dall'agente.
Viene serializzato in json e inviato all'aegis-link
*/

import com.google.gson.annotations.SerializedName;
import java.time.Instant;

/*
Rappresenta un evento di sistema rilevato dall'agente.
Viene serializzato in json e inviato all'aegis-link
*/

public class SystemEvent {
    @SerializedName("agentId")
    private String agentId;
    
    @SerializedName("pid")
    private long pid;

    @SerializedName("parentPid")
    private long parentPid;
    
    @SerializedName("parentProcessName")
    private String parentProcessName;
    
    @SerializedName("processName")
    private String processName;
    
    @SerializedName("processPath")
    private String processPath;
    
    @SerializedName("user")
    private String user;
    
    @SerializedName("os")
    private String os;
    
    @SerializedName("fileHash")
    private String fileHash;
    
    @SerializedName("eventType")
    private String eventType;
    
    @SerializedName("timestamp")
    private Instant timestamp;
    
    @SerializedName("hostname")
    private String hostname;
    
    @SerializedName("ipAddress")
    private String ipAddress;

    @SerializedName("threadCount")
    private int threadCount;

    @SerializedName("networkConnections")
    private com.google.gson.JsonElement networkConnections;

    @SerializedName("agentVersion")
    private String agentVersion;

    // Matrice feature dichiarata dal'agente (fleet management): il brain la
    // salva su Agent.capabilities e la UI la mostra nella pagina Agents.
    @SerializedName("capabilities")
    private com.google.gson.JsonElement capabilities;

    @SerializedName("commandLine")
    private String commandLine;

    @SerializedName("behavioralTags")
    private java.util.List<String> behavioralTags;

    // Event identity + sequencing (schema v2, M1 Fase 2). Tutti opzionali:
    // il brain accetta eventi v1 senza questi campi.
    @SerializedName("eventId")
    private String eventId;

    @SerializedName("schemaVersion")
    private int schemaVersion;

    @SerializedName("bootId")
    private String bootId;

    @SerializedName("seq")
    private Long seq;

    @SerializedName("tsMonotonicNs")
    private Long tsMonotonicNs;

    @SerializedName("tsWallNs")
    private Long tsWallNs;

    @SerializedName("procStartNs")
    private Long procStartNs;

    @SerializedName("sessionId")
    private String sessionId;

    @SerializedName("integrityLevel")
    private String integrityLevel;

    @SerializedName("signature")
    private String signature;

    @SerializedName("publisher")
    private String publisher;

    @SerializedName("proto")
    private String proto;

    @SerializedName("direction")
    private String direction;

    @SerializedName("containerId")
    private String containerId;

    @SerializedName("cgroup")
    private String cgroup;

    @SerializedName("netNamespace")
    private String netNamespace;

    @SerializedName("provenance")
    private String provenance;

    @SerializedName("quality")
    private String quality;

    @SerializedName("sampling")
    private String sampling;

    @SerializedName("dropReason")
    private String dropReason;

    public SystemEvent() {}

    public SystemEvent(String agentId, long pid, long parentPid, String parentProcessName,
                       String processName, String processPath, String user, String os,
                       String eventType) {
        this.agentId = agentId;
        this.pid = pid;
        this.parentPid = parentPid;
        this.parentProcessName = parentProcessName;
        this.processName = processName;
        this.processPath = processPath;
        this.user = user;
        this.os = os;
        this.eventType = eventType;
        this.timestamp = Instant.now();
        this.hostname = null;
        this.ipAddress = null;
        this.threadCount = 0;
        this.networkConnections = com.google.gson.JsonParser.parseString("[]");
        this.commandLine = "";
        this.behavioralTags = new java.util.ArrayList<>();
        this.eventId = java.util.UUID.randomUUID().toString();
        this.schemaVersion = 2;
    }

    // Getters e Setters
    public String getProcessPath()           { return processPath; }
    public void   setProcessPath(String v)   { this.processPath = v; }

    public String getAgentId()              { return agentId; }
    public void setAgentId(String v)        { this.agentId = v; }

    public long getPid()                    { return pid; }
    public void setPid(long v)              { this.pid = v; }

    public long getParentPid()              { return parentPid; }
    public void setParentPid(long v)        { this.parentPid = v; }

    public String getParentProcessName()    { return parentProcessName; }
    public void setParentProcessName(String v) { this.parentProcessName = v; }

    public String getProcessName()          { return processName; }
    public void setProcessName(String v)    { this.processName = v; }

    public String getUser()                 { return user; }
    public void   setUser(String v)         { this.user = v; }

    public String getOs()                   { return os; }
    public void   setOs(String v)           { this.os = v; }

    public String getFileHash()             { return fileHash; }
    public void   setFileHash(String v)     { this.fileHash = v; }

    public String getEventType()            { return eventType; }
    public void   setEventType(String v)    { this.eventType = v; }

    public Instant getTimestamp()           { return timestamp; }
    public void    setTimestamp(Instant v)  { this.timestamp = v; }

    public String getHostname()             { return hostname; }
    public void   setHostname(String v)     { this.hostname = v; }

    public String getIpAddress()            { return ipAddress; }
    public void   setIpAddress(String v)    { this.ipAddress = v; }

    public int getThreadCount()             { return threadCount; }
    public void setThreadCount(int v)       { this.threadCount = v; }

    public com.google.gson.JsonElement getNetworkConnections() { return networkConnections; }
    public void setNetworkConnections(String v) { this.networkConnections = com.google.gson.JsonParser.parseString(v); }

    public String getAgentVersion() { return agentVersion; }
    public void setAgentVersion(String v) { this.agentVersion = v; }
    public void setCapabilities(com.google.gson.JsonElement c) { this.capabilities = c; }

    public String getCommandLine() { return commandLine; }
    public void setCommandLine(String commandLine) { this.commandLine = commandLine; }

    public java.util.List<String> getBehavioralTags() { return behavioralTags; }
    public void setBehavioralTags(java.util.List<String> behavioralTags) { this.behavioralTags = behavioralTags; }
    public void addBehavioralTag(String tag) {
        if (this.behavioralTags == null) {
            this.behavioralTags = new java.util.ArrayList<>();
        }
        if (!this.behavioralTags.contains(tag)) {
            this.behavioralTags.add(tag);
        }
    }

    // Accessor schema v2 (tutti opzionali, mai obbligatori per il brain).
    public String getEventId() { return eventId; }
    public void setEventId(String v) { this.eventId = v; }

    public int getSchemaVersion() { return schemaVersion; }
    public void setSchemaVersion(int v) { this.schemaVersion = v; }

    public String getBootId() { return bootId; }
    public void setBootId(String v) { this.bootId = v; }

    public Long getSeq() { return seq; }
    public void setSeq(Long v) { this.seq = v; }

    public Long getTsMonotonicNs() { return tsMonotonicNs; }
    public void setTsMonotonicNs(Long v) { this.tsMonotonicNs = v; }

    public Long getTsWallNs() { return tsWallNs; }
    public void setTsWallNs(Long v) { this.tsWallNs = v; }

    public Long getProcStartNs() { return procStartNs; }
    public void setProcStartNs(Long v) { this.procStartNs = v; }

    public String getSessionId() { return sessionId; }
    public void setSessionId(String v) { this.sessionId = v; }

    public String getIntegrityLevel() { return integrityLevel; }
    public void setIntegrityLevel(String v) { this.integrityLevel = v; }

    public String getSignature() { return signature; }
    public void setSignature(String v) { this.signature = v; }

    public String getPublisher() { return publisher; }
    public void setPublisher(String v) { this.publisher = v; }

    public String getProto() { return proto; }
    public void setProto(String v) { this.proto = v; }

    public String getDirection() { return direction; }
    public void setDirection(String v) { this.direction = v; }

    public String getContainerId() { return containerId; }
    public void setContainerId(String v) { this.containerId = v; }

    public String getCgroup() { return cgroup; }
    public void setCgroup(String v) { this.cgroup = v; }

    public String getNetNamespace() { return netNamespace; }
    public void setNetNamespace(String v) { this.netNamespace = v; }

    public String getProvenance() { return provenance; }
    public void setProvenance(String v) { this.provenance = v; }

    public String getQuality() { return quality; }
    public void setQuality(String v) { this.quality = v; }

    public String getSampling() { return sampling; }
    public void setSampling(String v) { this.sampling = v; }

    public String getDropReason() { return dropReason; }
    public void setDropReason(String v) { this.dropReason = v; }
    
    @Override
    public String toString() {
        return String.format("[%s] pid=%-6d ppid=%-6d %-30s os=%-8s user=%s hostname=%s ip=%s",
                eventType, pid, parentPid, processName, os, user, hostname, ipAddress);
    }
}
