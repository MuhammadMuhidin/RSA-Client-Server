# Use the specified Python Alpine image
FROM python:3.10-alpine AS builder

# Set the working directory
WORKDIR /app

# Copy the requirements file and app code
COPY requirements.txt /app
COPY app.py /app
COPY /rsa /app/rsa

# Install dependencies
RUN pip install -r requirements.txt

# Specify the command to run your app
CMD ["python", "app.py"]
