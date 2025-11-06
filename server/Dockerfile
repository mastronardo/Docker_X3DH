# Use a lean Python image
FROM python:3.12.12-slim-trixie
USER root
RUN apt update && apt upgrade -y && apt autoremove -y && apt install -y sqlite3
WORKDIR /app

# Copy and install Python requirements
COPY . .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip-review --auto

# Expose the Flask port
EXPOSE 5001

# Create the directory for the SQLite database
RUN mkdir -p /app/data

CMD ["python3", "server.py"]