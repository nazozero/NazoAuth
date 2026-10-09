FROM docker.io/library/python:3.14.8-slim@sha256:c3e521df8b2b498a7a682e7e18676771cb80c6b75b8699af886b2d554ce40151

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

COPY .github/e2e-requirements.txt /tmp/e2e-requirements.txt

RUN pip install --no-cache-dir --require-hashes \
    -r /tmp/e2e-requirements.txt
