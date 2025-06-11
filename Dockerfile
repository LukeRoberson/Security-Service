# Use the custom base image
FROM lukerobertson19/base-os:latest
LABEL description="The security service for the AI assistant. Manages authentication, authorization, and cryptography."
LABEL version="1.0.0"

# Copy the rest of the application code
COPY . .
RUN chown -R appuser:appgroup /app

# Switch to the non-root user
USER appuser

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Start the application using uWSGI
CMD ["uwsgi", "--ini", "uwsgi.ini"]
