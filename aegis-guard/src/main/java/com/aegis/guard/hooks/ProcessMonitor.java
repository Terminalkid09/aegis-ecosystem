package com.aegis.guard.hooks;

import java.util.List;

import com.aegis.guard.models.SystemEvent;

/*
Interfaccia comune per il monitoraggio dei processi su tutti i OS
Ogni implementazione usa le api native del sistema operativo di destinazione
*/

public interface ProcessMonitor {

    // Avvia loop di monitoraggio
    void startMonitoring();

    // Ferma il monitoraggio
    void stopMonitoring();

    // Restituisce uno snapshot dei processi attivi al momento della chiamata
    List<SystemEvent> scanProcesses();
}