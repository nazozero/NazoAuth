FROM docker.io/library/python:3.15.0-slim@sha256:2da676046630d7bf14c6764ae1143dc7fa0377a53f94bf5a642f0b214aca5bce

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

COPY .github/e2e-requirements.txt /tmp/e2e-requirements.txt

RUN pip install --no-cache-dir --require-hashes \
    -r /tmp/e2e-requirements.txt
