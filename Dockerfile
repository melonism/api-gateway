# Alpine Linux with OpenJDK JRE
FROM openjdk:8-jre-alpine

RUN apk update && apk add bash

ARG JAR_FILE=target/api-gateway-0.0.1-SNAPSHOT.jar

COPY ${JAR_FILE} api-gateway.jar

# run application with this command line
CMD ["/usr/bin/java", "-jar", "-Dspring.profiles.active=default", "api-gateway.jar"]

EXPOSE 8011
