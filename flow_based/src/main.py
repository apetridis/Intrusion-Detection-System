import argparse
from helpers import capture_packets, select_network_interface
import warnings
from sklearn.exceptions import InconsistentVersionWarning

def main():
    # Choose model to detect from the initial command
    parser = argparse.ArgumentParser(description="Detect intrusions with machine learning models")
    parser.add_argument('-m', type=str, required=True, choices=['knn', 'trees', 'forest', 'linear_svm', 'abod', 'iforest', 'k_means', 'oneclass_svm'], help='Name of the model')
    arg = parser.parse_args()
    model = arg.m
    print("\033c", end="") # Clear the screen
    # Choose network interface to work with, from user prompt
    network_interface = select_network_interface()
    capture_packets(network_interface, model)

if __name__ == "__main__":
    warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
    warnings.filterwarnings("ignore", category=RuntimeWarning)
    main()
