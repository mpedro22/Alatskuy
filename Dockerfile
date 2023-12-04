# Use the official Python image from the Docker Hub
FROM python:3

# Set the working directory inside the container
ADD pabrikkk.py .

# Copy the current directory contents into the container at /app
COPY . /tubestst
WORKDIR /tubestst
RUN apt-get -y update && apt-get install -y curl gnupg

RUN curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add -
RUN curl https://packages.microsoft.com/config/debian/11/prod.list  \ 
> /etc/apt/sources.list.d/mssql-release.list

RUN exit
RUN apt-get -y update
RUN ACCEPT_EULA=Y apt-get install -y msodbcsql18

# Install any necessary dependencies
RUN pip install fastapi uvicorn python-multipart python-jose[cryptography] passlib[bcrypt] pyodbc

# Command to run the FastAPI server when the container starts
CMD ["uvicorn", "pabrikkk:app", "--host", "0.0.0.0", "--port", "80"]