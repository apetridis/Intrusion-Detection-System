# Import usefull libraries
import pandas as pd
from sklearn.model_selection import train_test_split
import joblib
from sklearn.metrics import classification_report
import argparse
from sklearn.utils import resample

from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.cluster import KMeans
from pyod.models.abod import ABOD


# function for oversampling the dataset
def makeOversample(_df, column):
    dfs_r = {}
    dfs_c = {}
    larger = -1
    ignore = ""

    # Find the class with the largest number of samples
    for c in _df[column].unique():
        dfs_c[c] = _df[_df[column] == c]
        if dfs_c[c].shape[0] > larger:
            larger = dfs_c[c].shape[0]
            ignore = c

    for c in dfs_c:
        if c == ignore:
            continue
        # Resample the minority class to match the size of the majority class
        dfs_r[c] = resample(dfs_c[c], 
                            replace=True,  # Set to True for oversampling
                            n_samples=larger,  # Match the size of the majority class
                            random_state=0)

    return pd.concat([dfs_r[c] for c in dfs_r] + [dfs_c[ignore]])

# Create a function for classifier
def clustering(cluster, X_train, X_test, y_test, model_name):
    cluster.fit(X_train)
    predicted = cluster.predict(X_test)
    # Change -1 values to 0 (all algorithms except k-means are clustering into -1, 0, 1)
    predicted = [0 if cluster == -1 else 1 for cluster in predicted]
    print(classification_report(y_test, predicted))
    joblib.dump(cluster, f"{model_name}.pkl")

def main():

    # Import datasets, concat and drop unneeded features
    mqtt_bruteforce = pd.read_csv('../../datasets/uniflow_mqtt_bruteforce.csv')
    normal = pd.read_csv('../../datasets/uniflow_normal.csv')
    scan_A = pd.read_csv('../../datasets/uniflow_scan_A.csv')
    scan_sU = pd.read_csv('../../datasets/uniflow_scan_sU.csv')
    sparta = pd.read_csv('../../datasets/uniflow_sparta.csv')
    data = pd.concat([mqtt_bruteforce, normal, scan_A, scan_sU, sparta], axis=0)
    data.drop(['ip_src', 'ip_dst', 'prt_src', 'prt_dst', 'proto'], axis='columns', inplace=True)


    # Remove 'num_urg_flags', 'mean_iat'
    data.drop(['num_urg_flags', 'mean_iat'], axis='columns', inplace=True)
    
    x = data.drop('is_attack', axis='columns')
    y = data['is_attack']


    # Split train and test set
    X_train, X_test, y_train, y_test = train_test_split(x, y, test_size = 0.25, random_state = 25)

    # Over and Sample the dataset
    merged_train_data = pd.concat([X_train, y_train], axis=1)
    merged_train_data = makeOversample(merged_train_data, 'is_attack')
    merged_train_data = merged_train_data.sample(frac=0.8, random_state=25)        

    X_train = merged_train_data.drop('is_attack', axis='columns')
    y_train = merged_train_data['is_attack']

    clusters = {
        'iforest': IsolationForest(contamination=0.000001),
        'oneclass_svm': OneClassSVM(nu=0.01),
        'k_means': KMeans(n_clusters=2),
        'abod': ABOD(contamination=0.01)
    }

    parser = argparse.ArgumentParser(description="Train unsupervised models for IDS")
    parser.add_argument('-c', type=str, required=True, choices=['iforest', 'oneclass_svm', 'k_means', 'abod'], help='Name of the clustering algorithm')
    arg = parser.parse_args()
    cluster = arg.c

    print(f"Start training {cluster}...")

    clustering(clusters[cluster], X_train, X_test, y_test, f"models/{cluster}")

if __name__ == "__main__":
    main()
