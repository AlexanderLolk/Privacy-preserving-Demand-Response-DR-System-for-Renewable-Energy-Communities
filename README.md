# Privacy-preserving-Demand-Response-DR-System-for-Renewable-Energy-Communities
Bachelor project 2025

This project is implementation of a privacy-preserving Demand Response (DR) program designed for a community of users who can participate in a energy consumption system.

## Download
You can download this project by downloading the release build or by cloning from the github.

## Installation
Once the project is on your local system, there are two way to run this project.

Our code requires Python, a library pycryptodome and another repository from tompetersen: https://github.com/tompetersen/threshold-crypto

if they are not already installed on your device, then the following will take care of that.

Note: These commands are run within the project folder.

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
docker build -t NAME-OF-YOUR-IMAGE .
```
Once done, all required components will have been installed within your image.

## Running the program

### Local
When running this project locally, ensure you have python on your device.

To run the program, use this command:
```
python main.py 
```

If you want to run any of the test in the /tests folder, use this command:
```
python -m tests.NAME-OF-THE-TEST
```
Note: When doing this, the .py does not need to added. <br>Example: python -m tests.test_performance

### Docker
The project can then be run with this command within the container:
```
docker run -it NAME-OF-YOUR-IMAGE python main.py
```

Running test in the container is done by:
```
docker run -it NAME-OF-YOUR-IMAGE python -m tests.NAME-OF-THE-TEST
```

## Edit components
If you want to run with different amount of smart meters, participants or selected participants, 
then there are three place to do this in main.

For the number of smart meters:
```
Line 20 in main: NUM_SM = 10
```

For the number of participants:
```
Line 25 in main: NUM_PARTICIPANTS = NUM_SM - 2
```
For the number of selected participants:
```
Line 28 in main: NUM_SELECTED = NUM_PARTICIPANTS // 2
```

## Edit baseline, consumption or target reduction
If you want to change the value for baseline, consumption or target reduction, then you have to edit three places:

For the value of the baseline:
```
Line 160 in main: m = 10
```

For the value of the consumption:
```
Line 153 in smartmeter: consume = random.randint(9, 10)
```

For the value of the target reduction:
```
Line 119 in DSO: target_reduction_value = 11
```