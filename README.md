# Thesis
My Thesis Repository (Creation of an Intrusion Detection System for IoT Network with MQTT Protocol)

## Virtual Enviroment
On a linux-based machine you can replicate doing the following:

- Install dependencies that are usefull for the python libraries
```
sudo apt-get install libpcap-dev
```
- Create virtual enviroment
```
python3 -m venv virtualenv
```
- Activate virtual enviroment
```
source virtualenv/bin/activate
```
- Install dependencies
```
pip install -r requirements.txt
```
- Deacivate virtual enviroment
```
deactivate
```
- Run python script with sudo priviledges from the bin of the venv
```
cd flow_based/src/
```
```
sudo virtualenv/bin/python3 main.py -m `model_name`
```

## Flow Based

### Training Supervised Machine Learning Algorithms 

Generated trained classifiers with the following commands:
- Change to data directory
```
cd flow_based/data/supervised
```
- Change to preprocessed or processed directory 
```
cd models_no-preprocess
```
or
```
cd models_preprocess
```
- Train models
```
python3 train-model.py -c linear > outputs/linear-output.txt
```
```
python3 train-model.py -c knn > outputs/knn-output.txt
```
```
python3 train-model.py -c rbf_svm > outputs/rbf_svm-output.txt
```
```
python3 train-model.py -c bayes > outputs/bayes-output.txt
```
```
python3 train-model.py -c trees > outputs/trees-output.txt
```
```
python3 train-model.py -c forest > outputs/forest-output.txt
```
```
python3 train-model.py -c linear_svm > outputs/linear_svm-output.txt
```

