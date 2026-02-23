# ─── Stage 1: Build ───────────────────────────────────────────────────────────
FROM ubuntu:25.10 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    make \
    python3 \
    pipx \
    && rm -rf /var/lib/apt/lists/*

RUN pipx install conan
ENV PATH="/root/.local/bin:$PATH"

RUN conan profile detect --force

WORKDIR /app

COPY conanfile.txt .

RUN conan install . --output-folder=build --build=missing -s build_type=Release

COPY . .

RUN make build PROJECT_DIR=/app

# ─── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM ubuntu:25.10 AS runtime

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app

COPY --from=builder /app/build/build/Release/src/bry_api .
COPY --from=builder /app/build/build/Release/src/bry_challenge_one .
COPY --from=builder /app/build/build/Release/src/bry_challenge_two .
COPY --from=builder /app/build/build/Release/src/bry_challenge_tree .

EXPOSE 8080

CMD ["./bry_api"]