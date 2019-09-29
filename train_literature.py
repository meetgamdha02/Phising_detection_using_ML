from sklearn import tree
from sklearn import svm
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import accuracy_score, confusion_matrix
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import train_test_split
#from utils import generate_data_set
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import sys

def load_data():
    '''
    Load data from CSV file
    '''
    # Load the training data from the CSV file
    #training_data = np.genfromtxt('dataset/train_dataset.csv', delimiter=',', dtype=np.int32)
    
    # Extract the inputs from the training data
    #inputs = training_data[:,:-1]

    # Extract the outputs from the training data
    #outputs = training_data[:, -1]

    training_data = pd.read_csv('dataset/train_dataset.csv')
    inputs = training_data.iloc[ : , :-1].values
    outputs = training_data.iloc[:, -1:].values

    # Split data for traning and testing
    training_inputs, testing_inputs,training_outputs, testing_outputs = train_test_split(inputs, outputs, test_size=0.3,random_state=110)
    print("Spilt of data:train_data|| test_data|| train_label|| test_label||")
    print(len(training_inputs),len(testing_inputs),len(training_outputs),len(testing_outputs))
    #finding spilt count in legitimate and phising
    #print("Train spilt count")
    #print(pd.value_counts(training_outputs))
    #training_outputs.value_counts()
    #print("Test spilt count")
    #print(pd.value_counts(testing_outputs))
    #testing_outputs.value_counts()
    # Return the four arrays
    return training_inputs, training_outputs, testing_inputs, testing_outputs

def run(classifier, name,train_inputs,train_outputs,test_inputs, test_outputs):
    '''
    Run the classifier to calculate the accuracy score
    '''
    # Train the decision tree classifier
    classifier.fit(train_inputs, train_outputs)

    # Use the trained classifier to make predictions on the test data
    predictions = classifier.predict(test_inputs)

    # Print the accuracy (percentage of phishing websites correctly predicted)
    accuracy = 100.0 * accuracy_score(test_outputs, predictions)
    print ("Accuracy score using {} is: {}\n".format(name, accuracy))

    #print confusion matrix
    mt=confusion_matrix(test_outputs, predictions)
    print(mt)


if __name__ == '__main__':
    '''
    Main function -
    Following are several models trained to detect phishing websites.
    '''

    # Load the training data
    train_inputs,train_outputs,test_inputs, test_outputs = load_data()
    # Decision tree
    classifier = tree.DecisionTreeClassifier()
    run(classifier, "Decision tree",train_inputs,train_outputs,test_inputs, test_outputs)

    # Random forest classifier (low accuracy)
    # classifier = RandomForestClassifier()
    # run(classifier, "Random forest",train_inputs,train_outputs,test_inputs, test_outputs)

    # Custom random forest classifier 1
    print ("Best classifier for detecting phishing websites.")
    classifier = RandomForestClassifier(n_estimators=500, max_depth=20, max_leaf_nodes=20000)
    run(classifier, "Random forest",train_inputs,train_outputs,test_inputs, test_outputs)
    #-------------Features Importance random forest
    training_data = pd.read_csv('dataset/train_dataset.csv')
    names = training_data.iloc[:,:-1].columns
    importances =classifier.feature_importances_
    sorted_importances = sorted(importances, reverse=True)
    indices = np.argsort(-importances)
    var_imp = pd.DataFrame(sorted_importances, names[indices], columns=['importance'])



    #-------------plotting variable importance
    plt.title("Variable Importances")
    plt.barh(np.arange(len(names)), sorted_importances, height = 0.7)
    plt.yticks(np.arange(len(names)), names[indices], fontsize=7)
    plt.xlabel('Relative Importance')
    plt.show()

    # Linear SVC classifier
    # classifier = svm.SVC(kernel='linear')
    # run(classifier, "SVC with linear kernel",train_inputs,train_outputs,test_inputs, test_outputs)

    # RBF SVC classifier
    # classifier = svm.SVC(kernel='rbf')
    # run(classifier, "SVC with rbf kernel",train_inputs,train_outputs,test_inputs, test_outputs)

    # Custom SVC classifier 1
    # classifier = svm.SVC(decision_function_shape='ovo', kernel='linear')
    # run(classifier, "SVC with ovo shape",train_inputs,train_outputs,test_inputs, test_outputs)

    # Custom SVC classifier 2
    # classifier = svm.SVC(decision_function_shape='ovo', kernel='rbf')
    # run(classifier, "SVC with ovo shape",train_inputs,train_outputs,test_inputs, test_outputs)

    # NuSVC classifier
    # classifier = svm.NuSVC()
    # run(classifier, "NuSVC",train_inputs,train_outputs,test_inputs, test_outputs)

    # OneClassSVM classifier
    print( "Worst classifier for detecting phishing websites.")
    classifier = svm.OneClassSVM(gamma=1.7)
    run(classifier, "One Class SVM",train_inputs,train_outputs,test_inputs, test_outputs)

    # print "K nearest neighbours algorithm."
    # nbrs = KNeighborsClassifier(n_neighbors=5, algorithm='ball_tree')
    # run(nbrs, "K nearest neighbours",train_inputs,train_outputs,test_inputs, test_outputs)

    # Gradient boosting classifier
    # classifier = GradientBoostingClassifier()
    # run(classifier, "GradientBoostingClassifier",train_inputs,train_outputs,test_inputs, test_outputs)

    # Take user input and check whether its phishing URL or not.
    if len(sys.argv) > 1:
        #data_set = generate_data_set(sys.argv[1])

        # Reshape the array
        data_set = np.array(data_set).reshape(1, -1)

        # Load the date
        train_inputs, test_inputs,train_outputs, test_outputs = load_data()

        # Create and train the classifier
        classifier = RandomForestClassifier(n_estimators=500, max_depth=15, max_leaf_nodes=10000)
        classifier.fit(train_inputs, train_outputs)

        print(classifier.predict(data_set))