FROM openjdk:25-jdk-slim
WORKDIR /app
COPY target/aegis-guard-1.0-SNAPSHOT.jar guard.jar
# Note: Monitoring host processes from inside a container requires special flags (--pid=host)
ENTRYPOINT ["java", "-jar", "guard.jar"]
