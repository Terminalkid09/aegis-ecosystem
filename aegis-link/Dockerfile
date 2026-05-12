# ─── Build stage ──────────────────────────────────────────────────────────────
FROM eclipse-temurin:21-jdk-alpine AS build
RUN apk add --no-cache maven
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline -B 2>/dev/null || true
COPY src ./src
RUN mvn clean package -Dmaven.test.skip=true -B

# ─── Runtime stage ────────────────────────────────────────────────────────────
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar

# Security: Run as non-root user
RUN addgroup -S aegis && adduser -S aegis -G aegis
RUN chown aegis:aegis /app/app.jar
USER aegis

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
