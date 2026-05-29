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

    public SystemEvent() {}

    public SystemEvent(String agentId, long pid, String processName,
                       String processPath, String user, String os,
                       String eventType) {
        this.agentId = agentId;
        this.pid = pid;
        this.processName = processName;
        this.processPath = processPath;
        this.user = user;
        this.os = os;
        this.eventType = eventType;
        this.timestamp = Instant.now();
        this.hostname = null;
        this.ipAddress = null;
    }

    // Getters e Setters
    public String getProcessPath()           { return processPath; }
    public void   setProcessPath(String v)   { this.processPath = v; }

    public String getAgentId()              { return agentId; }
    public void setAgentId(String v)        { this.agentId = v; }

    public long getPid()                    { return pid; }
    public void setPid(long v)              { this.pid = v; }

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
    
    @Override
    public String toString() {
        return String.format("[%s] pid=%-6d %-30s os=%-8s user=%s hostname=%s ip=%s",
                eventType, pid, processName, os, user, hostname, ipAddress);
    }
}
