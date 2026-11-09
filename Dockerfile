FROM python:3.13-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 TZ=Europe/Zurich
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && groupadd --gid 10001 triage \
    && useradd --uid 10001 --gid triage --no-create-home triage \
    && mkdir /data && chown triage:triage /data
COPY logtriage ./logtriage
COPY config ./config
USER 10001:10001
VOLUME ["/data"]
ENTRYPOINT ["python", "-m", "logtriage"]
CMD ["watch"]
