# Thesis repository
This repository contains the code and documentation for my thesis project, titled "Real-time security anomaly detection for smart infrastructures in the context of the Internet-of-Things"

## Table of Contents
- [Virtual Enviroment Setup](#virtual-enviroment-setup)
  - [Install dependencies that are usefull for the python libraries](#install-dependencies-that-are-usefull-for-the-python-libraries)
  - [Create virtual enviroment](#create-virtual-enviroment)
  - [Activate virtual enviroment](#activate-virtual-enviroment)
  - [Deactivate virtual enviroment](#deactivate-virtual-enviroment)
- [Machine Learning Training models](#machine-learning-training-models)
  - [Install python requirements](#install-python-requirements)
  - [Create folders needed](#create-folders-needed)
  - [Train models](#train-models)
- [Detection tool](#detection-tool)
  - [Install python requirements](#install-python-requirements2)

## Virtual Enviroment Setup
On a linux-based machine you can replicate the training and detection doing the following:

### Install dependencies that are usefull for the python libraries
```
sudo apt-get install libpcap-dev
```
### Create virtual enviroment
```
python3 -m venv virtualenv
```
### Activate virtual enviroment
```
source virtualenv/bin/activate
```
### Deactivate virtual enviroment
```
deactivate
```

## Machine Learning Training models

### Install python requirements
```
pip install -r training_requirements.txt
```
### Create folders needed
Depending on your operating system this is optional
  - Create folder to store reports
```
mkdir flow_based/src/reports
```
  - Create folder to store machine learning models
```
mkdir flow_based/data/supervised/outputs
```
```
mkdir flow_based/data/unsupervised/outputs
```
### Train models
- Depending on which models you need to train you have to go to the specific directory:
  - For supervised models:
```
cd flow_based/data/supervised
```
  - For unsupervised models:
```
cd flow_based/data/unsupervised
```
Also depending on the features that you need your algorithm trained with, go to the specific directory:
  - For all features:
```
cd all_features
```
  - For selected features:

```
cd selected_features
```
Use the following commands after the redirection to the specific folders to train the models:
- Supervised
  - Linear model
```
python3 train-model.py -c linear > outputs/linear-output.txt
```
  - K-Nearest Neighbour
```
python3 train-model.py -c knn > outputs/knn-output.txt
```
  - Support Vector Machine with RBF kerner
```
python3 train-model.py -c rbf_svm > outputs/rbf_svm-output.txt
```
  - Gaussiane Nayes Bayes
```
python3 train-model.py -c bayes > outputs/bayes-output.txt
```
  - Decision Tree
```
python3 train-model.py -c trees > outputs/trees-output.txt
```
  - Random Forest
```
python3 train-model.py -c forest > outputs/forest-output.txt
```
  - Support Vector Machine with linear kernel
```
python3 train-model.py -c linear_svm > outputs/linear_svm-output.txt
```
- Unsupervised
  - Isolation Forest
```
python3 train-model.py -c iforest > outputs/iforest.txt
```
  - One Class Support Vector Machine
```
python3 train-model.py -c oneclass_svm > outputs/oneclass_svm.txt
```
  - K-Means
```
python3 train-model.py -c k_means > outputs/k_means.txt
```
  - Angle-Based OD
```
python3 train-model.py -c abod > outputs/abod.txt
```


## Detection tool

### Install python requirements
```
pip install -r detection_requirements.txt
```
### Run tool
The tool needs sudo rights, so the best thing to do is to install the requirements on the virtual enviroment and then run the script right from the virtual enviroment python interpreter.
- Change directory
```
cd flow_based/src/
```
- Run tool and select the model name from one of the models that you train on the previous section. 
```
sudo virtualenv/bin/python3 main.py -m `model_name`
```


