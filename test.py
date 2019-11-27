# Purpose - Receive the call for testing a page from the Chrome extension and return the result (SAFE/PHISHING)
# for display. This file calls all the different components of the project (The ML model, features_extraction) and
# consolidates the result.

import joblib
import feature_extraction
import sys
import numpy as np

from single_extract import LOCALHOST_PATH, DIRECTORY_NAME
import single_extract

def get_prediction_from_url(test_url):
    features_test = single_extract.main(test_url)
    # Due to updates to scikit-learn, we now need a 2D array as a parameter to the predict function.
    features_test = np.array(features_test).reshape((1, -1))

    clf = joblib.load(LOCALHOST_PATH + DIRECTORY_NAME + '/classifier/random_forest.pkl')

    pred = clf.predict(features_test)
    return int(pred[0])


def main():
    url = sys.argv[1]

    prediction = get_prediction_from_url(url)

    # Print the probability of prediction (if needed)
    # prob = clf.predict_proba(features_test)
    # print 'Features=', features_test, 'The predicted probability is - ', prob, 'The predicted label is - ', pred
    #    print "The probability of this site being a phishing website is ", features_test[0]*100, "%"

    if prediction == 1:
        # print "The website is safe to browse"
        print("SAFE")
    elif prediction == -1:
        # print "The website has phishing features. DO NOT VISIT!"
        print("PHISHING")

        # print 'Error -', features_test


if __name__ == "__main__":
    main()
