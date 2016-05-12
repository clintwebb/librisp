FROM ubuntu
RUN apt-get update && apt-get install -y libevent-dev && rm -rf /var/lib/apt/lists/*

COPY librisp64.so.1.0.0 /usr/lib/
RUN ln -s /usr/lib/librisp64.so.1.0.0 /usr/lib/librisp64.so
RUN ln -s /usr/lib/librisp64.so /usr/lib/librisp64.so.2
COPY risp_chat_server /usr/bin/

ENTRYPOINT ["/usr/bin/risp_chat_server"]
EXPOSE 13555



