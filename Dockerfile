FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN apt-get update && \
    apt-get -y install gcc && \
    pip install -r requirements.txt && \
    pip install PyMuPDF && \
    python -m spacy download en_core_web_lg
COPY . .
RUN echo '#!/bin/bash\nuvicorn src.main:app --host 0.0.0.0 --port ${PORT} --reload' > /usr/bin/app-run && \
    chmod +x /usr/bin/app-run

CMD ["app-run"]
