FROM docker.io/library/python:3.15.2-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

COPY .github/e2e-requirements.txt /tmp/e2e-requirements.txt

RUN pip install --no-cache-dir --require-hashes \
    -r /tmp/e2e-requirements.txt
