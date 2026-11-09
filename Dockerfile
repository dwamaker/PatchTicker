# The collector: one image for every box (Oracle main, .104 standby). Settings and keys come from the
# environment file at run time, never from the image.
FROM python:3.13-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY collector/ collector/
# The collector reads vendor spellings from web/vendors.json (collector/incidents.py).
COPY web/vendors.json web/vendors.json

USER nobody
ENV PYTHONUNBUFFERED=1
# One cycle. compose.yaml replaces this with a loop that runs it every 10 minutes.
CMD ["python", "-m", "collector"]
