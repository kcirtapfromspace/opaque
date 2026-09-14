# Layer only the pinned CPU engine on the existing disposable service host.
# The 105 MB model remains a verified, read-only runtime mount.
ARG CONTAINED_IMAGE=opaque-contained-ssh:local
FROM ${CONTAINED_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends cmake build-essential \
    && rm -rf /var/lib/apt/lists/* \
    && git init /tmp/llama-source \
    && git -C /tmp/llama-source config core.abbrev 9 \
    && git -C /tmp/llama-source fetch --depth 1 https://github.com/ggml-org/llama.cpp.git c1d0e7a004015f23bc0233470b747b596f29b264 \
    && git -C /tmp/llama-source checkout --detach FETCH_HEAD \
    && test "$(git -C /tmp/llama-source rev-parse HEAD)" = c1d0e7a004015f23bc0233470b747b596f29b264 \
    && cmake -S /tmp/llama-source -B /tmp/llama-build \
       -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
       -DGGML_NATIVE=OFF -DGGML_CUDA=OFF -DGGML_METAL=OFF -DGGML_VULKAN=OFF -DGGML_OPENMP=OFF \
       -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF -DLLAMA_BUILD_APP=OFF \
       -DLLAMA_BUILD_TOOLS=ON -DLLAMA_BUILD_SERVER=ON -DLLAMA_BUILD_UI=OFF \
       -DLLAMA_OPENSSL=OFF -DLLAMA_SUBPROCESS=OFF \
    && cmake --build /tmp/llama-build --target llama-server --parallel 2 \
    && mkdir -p /opt/opaque-model \
    && cp /tmp/llama-build/bin/llama-server /opt/opaque-model/llama-server \
    && printf '%s\n' c1d0e7a004015f23bc0233470b747b596f29b264 > /opt/opaque-model/source-commit \
    && chmod 755 /opt/opaque-model/llama-server \
    && rm -rf /tmp/llama-source /tmp/llama-build
