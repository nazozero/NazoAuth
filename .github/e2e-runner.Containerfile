FROM python:3.13-slim

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

RUN pip install --no-cache-dir \
    requests \
    "psycopg[binary]" \
    redis \
    argon2-cffi \
    pyjwt \
    cryptography \
    aiosmtpd
