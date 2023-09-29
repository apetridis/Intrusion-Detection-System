# Import usefull libraries
import pandas as pd
from sklearn.model_selection import train_test_split
import joblib
from sklearn.metrics import classification_report
from sklearn.svm import SVC, LinearSVC
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
import argparse
from sklearn.utils import resample


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
def classify(classifier, X_train, y_train, X_test, y_test, model_name):
    classifier.fit(X_train, y_train)
    predicted = classifier.predict(X_test)
    print(classification_report(y_test, predicted))
    joblib.dump(classifier, f"{model_name}.pkl")

def main():

    # Import datasets, concat and drop unneeded features
    mqtt_bruteforce = pd.read_csv('../../datasets/uniflow_mqtt_bruteforce.csv')
    normal = pd.read_csv('../../datasets/uniflow_normal.csv')
    scan_A = pd.read_csv('../../datasets/uniflow_scan_A.csv')
    scan_sU = pd.read_csv('../../datasets/uniflow_scan_sU.csv')
    sparta = pd.read_csv('../../datasets/uniflow_sparta.csv')
    data = pd.concat([mqtt_bruteforce, normal, scan_A, scan_sU, sparta], axis=0)
    data.drop(['ip_src', 'ip_dst', 'prt_src', 'prt_dst', 'proto'], axis='columns', inplace=True)

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

    classifiers = {
        'linear': LogisticRegression(random_state = 25, verbose=True, max_iter=5000, C=0.01, solver='sag'),
        'knn': KNeighborsClassifier(n_jobs=-1),
        'rbf_svm': SVC(kernel = 'rbf', random_state = 25, gamma='scale', verbose=True, shrinking=False),
        'bayes': GaussianNB(),
        'trees': DecisionTreeClassifier(criterion = 'entropy', random_state = 25),
        'forest': RandomForestClassifier(n_estimators = 10, criterion = 'entropy', random_state = 25, verbose=True, n_jobs=-1),
        'linear_svm': LinearSVC(random_state = 25, verbose=True)
    }

    parser = argparse.ArgumentParser(description="Train different models for using them to detect network intrusions")
    parser.add_argument('-c', type=str, required=True, choices=['linear', 'knn', 'rbf_svm', 'bayes', 'trees', 'forest', 'linear_svm'], help='Name of the classifier')
    arg = parser.parse_args()
    classifier = arg.c

    print(f"Start training {classifier}...")

    classify(classifiers[classifier], X_train, y_train, X_test, y_test, f"models/{classifier}")

if __name__ == "__main__":
    main()
