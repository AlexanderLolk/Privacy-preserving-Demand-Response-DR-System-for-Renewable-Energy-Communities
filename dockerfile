# Use a clean Python image
FROM python:3.10-slim

# Set the working directory
WORKDIR /app

# INSTALL GIT 
RUN apt-get update && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy your project files
COPY . .

# Try to install the project
RUN pip install .

