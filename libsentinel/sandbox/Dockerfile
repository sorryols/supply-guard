# Образ пісочниці LibSentinel для динамічного аналізу (етап 5 методу).
# Збирається командою:  libsentinel sandbox-build
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends strace gcc libc6-dev git \
 && rm -rf /var/lib/apt/lists/*

# Бекенди збирання, щоб встановлювати sdist без доступу до мережі
RUN pip install --no-cache-dir setuptools wheel hatchling hatch-vcs flit-core poetry-core \
    setuptools-scm pdm-backend cython maturin scikit-build-core meson-python

RUN useradd -m -u 1000 sandbox
COPY runner.py /opt/libsentinel/runner.py

USER sandbox
WORKDIR /home/sandbox
ENTRYPOINT ["python3", "/opt/libsentinel/runner.py"]
