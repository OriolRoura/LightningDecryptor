# Dockerfile matching Polar's pattern exactly but building custom LND
FROM debian:stable-slim

ENV PATH=/opt/lnd:$PATH

# Install dependencies exactly like Polar (plus build tools)
RUN apt-get update -y \
  && apt-get install -y curl gosu wait-for-it bash ca-certificates \
                        build-essential git make \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Install Go for building (temporary)
RUN curl -SL https://go.dev/dl/go1.23.9.linux-amd64.tar.gz | tar -xzC /usr/local
ENV PATH=/usr/local/go/bin:$PATH

# Copy source and build LND (replacing Polar's download step)
# Exclude standalone analysis tools that have package main
COPY . /go/src/github.com/lightningnetwork/lnd
WORKDIR /go/src/github.com/lightningnetwork/lnd

# Remove standalone tools that conflict with package lnd (keep cmd/ directory)
# Only remove files that are clearly analysis tools, not core LND files
RUN rm -f brute_force*.go *decryptor*.go *analysis*.go amount_bug_test.go debug_frame*.go test_all_nonces.go test_role_swap.go lightning_analysis.go failure_analysis.go enhanced_decryptor.go nonce_analysis.go smart_decryptor.go general_decryptor*.go brontide_session_decryptor.go implementation.go || true

# Build LND with your modifications
RUN make && make install tags="signrpc walletrpc chainrpc invoicesrpc peersrpc"

# Create /opt/lnd and move binaries there (exactly like Polar does)
RUN mkdir -p /opt/lnd \
  && (cp /usr/local/bin/lnd /opt/lnd/ || cp /go/bin/lnd /opt/lnd/ || find / -name "lnd" -type f -executable 2>/dev/null | head -1 | xargs -I {} cp {} /opt/lnd/) \
  && (cp /usr/local/bin/lncli /opt/lnd/ || cp /go/bin/lncli /opt/lnd/ || find / -name "lncli" -type f -executable 2>/dev/null | head -1 | xargs -I {} cp {} /opt/lnd/) \
  && chmod +x /opt/lnd/lnd /opt/lnd/lncli

# Clean up build dependencies and Go installation
RUN apt-get remove -y build-essential git make \
  && rm -rf /usr/local/go /go \
  && apt-get autoremove -y \
  && apt-get clean

# Add bash completion exactly like Polar
RUN curl -SLO https://raw.githubusercontent.com/lightningnetwork/lnd/master/contrib/lncli.bash-completion \
  && mkdir -p /etc/bash_completion.d \
  && mv lncli.bash-completion /etc/bash_completion.d/ \
  && curl -SLO https://raw.githubusercontent.com/scop/bash-completion/master/bash_completion \
  && mv bash_completion /usr/share/bash-completion/

# Copy entrypoint exactly like Polar
COPY docker-entrypoint.sh /entrypoint.sh
# COPY bashrc /home/lnd/.bashrc  # Uncomment if you have this file

RUN chmod a+x /entrypoint.sh

VOLUME ["/home/lnd/.lnd"]

EXPOSE 9735 8080 10000

ENTRYPOINT ["/entrypoint.sh"]

CMD ["lnd"]
