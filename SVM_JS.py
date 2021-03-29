# This script serves to and validate the findings of Likarish, Jung, & Jo in their paper titled
# 'Obfuscated Malicious Javascript Detection using Classification Techniques'. The feature vectors are:
#
# This script was written by z5195413 Simon Smalley and z5087415 Lachlan Cairns for ZEIT8025 - Reverse Engineering Malware

import pandas as pd
import matplotlib.pyplot as pyplot
import seaborn as sbn
import numpy as np
import time
from sklearn import svm
from sklearn.model_selection import train_test_split, KFold, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix, f1_score

# Open CSV as dataframe
js_scripts_raw = pd.read_csv("E:\\js_dataset.csv")
print("Shape of the dataset is:\n", js_scripts_raw.shape,'\n')
print("Dataset columns:\n", js_scripts_raw.columns,'\n')

# Heatmap correlation matrix - just because I'm curious
matrix = js_scripts_raw.corr()
figure = pyplot.figure(figsize=(10,10))
sbn.heatmap(matrix,square=True)

def SVM_function(input_file, k):
    
    df = input_file
    
    # x = data, y = classification
    X = df.iloc[:,:-1]
    y = df.iloc[:,-1]
    
    # How many cross validation folds (passed in k)?
    kf = KFold(n_splits=k, random_state=None)
    SVM = svm.SVC(kernel='linear')
    
    prec_score = []
    recall_score = []
    F1_score = []
    
    start = time.time()
    counter = 0
    
    for train_index, test_index in kf.split(X):
        X_train, X_test = X.iloc[train_index,:],X.iloc[test_index,:]
        y_train, y_test = y[train_index], y[test_index]
    
        scaler = StandardScaler()
        X_train = scaler.fit_transform(X_train)
        X_test = scaler.fit_transform(X_test)
        
        SVM.fit(X_train, y_train)
        pred_values = SVM.predict(X_test)
        
        F1 = f1_score(y_test, pred_values, average='binary')
        cm = confusion_matrix(y_test, pred_values)
        prec, recall = calc_stats(cm) 
        
        print('CM (TN, FN, TP, FP): ', cm)
        prec_score.append(prec)
        recall_score.append(recall)
        F1_score.append(F1)
    
    avg_prec_score = sum(prec_score)/k
    avg_recall_score = sum(recall_score)/k
    avg_F1_score = sum(F1_score)/k
    
    print('Average precision:',avg_prec_score)
    print('Average recall:',avg_recall_score)
    print('Average F1 score:',avg_F1_score)
    
    print('Processing time:', round((time.time() - start),2), 'seconds')

def calc_stats(CM):
    TN = CM[0][0]
    FN = CM[0][1]
    TP = CM[1][1]
    FP = CM[1][0]
    
    prec = TP / (TP + FP)
    recall = TP / (TP + FN)
    
    return prec, recall
    
if __name__ == "__main__":
        
    # Cross-validation
    SVM_function(js_scripts_raw, 10)
