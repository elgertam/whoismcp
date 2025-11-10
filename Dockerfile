FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install uv
RUN pip install uv

# Copy project files
COPY pyproject.toml ./
COPY README.md ./
COPY src/ ./src/

# Install dependencies
RUN uv pip install --system -e .

# Expose port
EXPOSE 8080

# Run SSE server
CMD ["python", "-m", "uvicorn", "whoismcp.sse_server:create_app", "--host", "0.0.0.0", "--port", "8080", "--factory"]
