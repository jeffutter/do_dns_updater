FROM alpine AS setup
RUN adduser -D -H updater 
COPY ./do-dns-updater /usr/local/bin/
RUN chmod 755 /usr/local/bin/do-dns-updater

FROM scratch

COPY --from=setup /etc/passwd /etc/passwd
COPY --from=setup /usr/local/bin/do-dns-updater /usr/local/bin/do-dns-updater
USER updater

CMD ["/usr/local/bin/do-dns-updater"]
