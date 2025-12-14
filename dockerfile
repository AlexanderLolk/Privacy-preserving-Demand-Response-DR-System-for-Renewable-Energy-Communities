# 1. Use a clean Python image
FROM python:3.10-slim

# 2. Set the working directory
WORKDIR /app

# 3. INSTALL GIT (This is the missing piece)
# We update the package list and install git, then clean up to keep the image small
RUN apt-get update && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

# 4. Copy your project files
COPY . .

# 5. Try to install the project
RUN pip install .

# 6. Your command (replace with your actual script name)
CMD ["my-app-command"]