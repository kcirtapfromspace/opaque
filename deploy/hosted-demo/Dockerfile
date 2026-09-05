FROM debian:bookworm-slim
RUN apt-get update && apt-get install --no-install-recommends -y python3 openssl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/opaque
COPY deploy/hosted-demo/bin/opaque-metrics /opt/opaque/bin/opaque-metrics
COPY deploy/hosted-demo/runtime.py deploy/hosted-demo/controller.py deploy/hosted-demo/credit_source.py deploy/hosted-demo/model_profiles.py /opt/opaque/deploy/hosted-demo/
COPY scripts/metrics_chat_dogfood.py /opt/opaque/scripts/metrics_chat_dogfood.py
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 7383:7383
EXPOSE 8080
ENTRYPOINT ["python3", "/opt/opaque/deploy/hosted-demo/runtime.py"]
