FROM eclipse-temurin:21-jdk-alpine AS build
RUN apk add --no-cache maven
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline -B
COPY src ./src
RUN mvn clean package -Dmaven.test.skip=true -B

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY --from=build /app/target/aegis-guard.jar app.jar

# Security: Run as non-root user
RUN addgroup -S aegis && adduser -S aegis -G aegis
RUN mkdir -p /app/data && chown -R aegis:aegis /app
USER aegis

ENTRYPOINT ["java", "-jar", "app.jar"]
