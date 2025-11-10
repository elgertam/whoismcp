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

# Expose port (can be overridden by environment)
EXPOSE 8080

# Run SSE server using main entry point which respects PORT/BIND_PORT env vars
CMD ["python", "-m", "whoismcp.sse_server"]
