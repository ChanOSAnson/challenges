FROM pwn.red/jail

ARG port
ENV JAIL_PORT ${port}
ARG binary
ENV BINARY_NAME ${binary}
COPY --from=ubuntu:23.04 / /srv
COPY ${BINARY_NAME} /srv/app/run
RUN chmod 755 /srv/app/run
