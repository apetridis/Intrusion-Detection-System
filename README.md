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
    - [Supervised](#supervised)
    - [Unsupervised](#unsupervised)
- [Detection tool](#detection-tool)
  - [Install python requirements](#install-python-requirements-1)
  - [Run tool](#run-tool)

## Virtual Enviroment Setup
On a linux-based machine you can replicate the training and detection doing the following:

### Install dependencies that are usefull for the python libraries
```
sudo apt-get install python3-dev libpcap-dev g++
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
#### Supervised
  - Linear model
    ```
    python3 train-model.py -c linear 
    ```
  - K-Nearest Neighbour
    ```
    python3 train-model.py -c knn 
    ```
  - Support Vector Machine with RBF kerner
    ```
    python3 train-model.py -c rbf_svm 
    ```
  - Gaussiane Nayes Bayes
    ```
    python3 train-model.py -c bayes 
    ```
  - Decision Tree
    ```
    python3 train-model.py -c trees 
    ```
  - Random Forest
    ```
    python3 train-model.py -c forest 
    ```
  - Support Vector Machine with linear kernel
    ```
    python3 train-model.py -c linear_svm 
    ```
#### Unsupervised
  - Isolation Forest
    ```
    python3 train-model.py -c iforest 
    ```
  - One Class Support Vector Machine
    ```
    python3 train-model.py -c oneclass_svm 
    ```
  - K-Means
    ```
    python3 train-model.py -c k_means 
    ```
  - Angle-Based OD
    ```
    python3 train-model.py -c abod 
    ```


## Detection tool

### Install python requirements
```
pip install -r detection_requirements.txt
```
### Run tool
The tool needs sudo rights, so the best thing to do is to install the requirements on the virtual enviroment and then run the script right from the virtual enviroment python interpreter.

- Run tool and select the model name from one of the models that you train on the previous section. 
```
sudo virtualenv/bin/python3 flow_based/src/main.py -m `model_name`
```
Model name can be one of the following:
- Supervised algorithms:
  - K-nearest neighbors: ```knn```
  - Random Forest: ```forest```
  - Linear Support Vector Machine: ```linear_svm```
  - Decision Trees: ```trees```
- Unsupervised algorithms:
  - Angle-Based Outlier Detection: ```abod```
  - Isolation Forest: ```iforest```
  - One Class Support Vector Machine: ```oneclass_svm```
  - K-means: ```k_means```


