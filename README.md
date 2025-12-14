# Privacy-preserving-Demand-Response-DR-System-for-Renewable-Energy-Communities
Bachelor project 2025

This project is implementation of a privacy-preserving Demand Response (DR) program designed for a community of users who can participate in a energy consumption system.

## Download
You can download this project by downloading the release build or by cloning from the github.

## Installation
Once the project is on your local system, there are two way to run this project.

Our code requires Python, a library pycryptodome and another repository from tompetersen: https://github.com/tompetersen/threshold-crypto

if they are not already installed on your device, the following will take care of that.

Note: These commands are ran within the project folder.

### Local installation
To install all of these run this in your terminal:
```
pip install .
```
This will create a clone of the mentioned repository in temporary folder and install the required components.

### Docker installation
If you have docker, is it also possible to setup a image container for this project.

To setup a image for this project, first run this command:
```
docker build -t name-of-your-image .
```
Once install all required components will be within your image.

## Running the program

### local
When running this project locally, ensure you have python on your device.

To run the program, use this command:
```
python main.py 
```

### docker
The project can then be run with this command within the container:
```
docker run -it name-of-your-image python Main.py
```