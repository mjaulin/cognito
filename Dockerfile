FROM java:8-jre-alpine

COPY target/cognito-1.0-*.jar /opt/app.jar

ENTRYPOINT [ "java", "-jar", "/opt/app.jar" ]