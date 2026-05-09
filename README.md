# Aegis Ecosystem

## Overview
Aegis is a distributed EDR (Endpoint Detection and Response) ecosystem designed for high-performance security monitoring and threat analysis.

## Project Structure
- **aegis-guard**: Java-based agent using JNA for native system monitoring.
- **aegis-link**: Spring Boot gateway for data ingestion and buffering.
- **aegis-brain**: Python/FastAPI engine for threat detection and heuristics.

## Setup
1. Ensure Docker is installed.
2. Run `docker-compose up -d` to start infrastructure and backend services.
3. Build and run `aegis-guard` on the target endpoint.
