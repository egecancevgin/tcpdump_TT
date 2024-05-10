# Bu kodlar main.py dosyası içinde bulunmalıdır.

import pandas as pd
from scapy.all import rdpcap
import re
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LinearRegression
from sklearn.metrics import mean_squared_error
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestRegressor
from sklearn.neural_network import MLPRegressor
from scipy import sparse
from sklearn.preprocessing import LabelEncoder
import numpy as np




""" Usage:
  $ pip install scapy
  $ pip install pandas
  $ pip install scikit-learn
"""


def filter_pcap(pcap_file):
    """ Reads and forms the .pcap file into a Pandas DataFrame. """
    packets = rdpcap(pcap_file)
    i = 0
    packet_info = []
    bulk_list = []
    df = pd.DataFrame(columns=['Summary', 'Packet Size'])
    for packet in packets:
      #print(packet.summary(), "\n")
      i += 1
      #print(dir(packet))
      layer_info = str(packet.getlayer(0))
      layer_info += "/"
      layer_info += str(len(packet))
      packet_info.append(layer_info)
   
    for elm in packet_info:
       splitters = r"[ />]"
       splitted = re.split(splitters, elm)
       filtered_parts = list(filter(
          lambda x: x.strip() and x != '??' and x != 'v??', splitted
       ))
       filtered_parts.remove('CookedLinuxV2')
       try:
          filtered_parts.remove("who")
          filtered_parts.remove("has")
          filtered_parts.remove("is")
       except:
          pass
       
       # Pop and append operation
       pck_size = filtered_parts.pop()
       text = text = " ".join(filtered_parts)
       text = text.strip()
       df = pd.concat([df, pd.DataFrame(
          {'Summary': [text],
           'Packet Size': [pck_size]})],
           ignore_index=True
       )
    df['Summary'] = df['Summary'].str.strip()
    return df
    

def packet_size_lr(df):
   """ Trains a Linear Regression model and for packet size prediction. """
   #X_text = df[['Network Protocol', 'Transport Protocol', 'Operation', 'Summary']]
   shuffled_df = df.sample(frac=1, random_state=42).reset_index(drop=True)
   X_text = df[['Network Protocol', 'Transport Protocol', 'Operation']]
   y = df['Packet Size']
   #vectorizer = TfidfVectorizer()
   #X_text_transformed = vectorizer.fit_transform(X_text['Summary'])
   
   X_categorical = pd.get_dummies(X_text[[
      'Network Protocol', 'Transport Protocol', 'Operation'
   ]])
   #X = sparse.hstack([X_text_transformed, X_categorical])
   #X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
   X_train, X_test, y_train, y_test = train_test_split(X_categorical, y, test_size=0.2, random_state=42)
    
   model = LinearRegression()
   model.fit(X_train, y_train)
   y_pred = model.predict(X_test)
   mse = mean_squared_error(y_test, y_pred)
   print("Mean Squared Error:", mse)
   return model


def packet_size_rf(df):
   """ Trains a Random Forest model for packet size prediction. """
   vectorizer = TfidfVectorizer()
   X_text = vectorizer.fit_transform(df['Summary'])
   y = df['Packet Size']
   X_train, X_test, y_train, y_test = train_test_split(
      X_text, y, test_size=0.2, random_state=42
   )
   model = RandomForestRegressor(n_estimators=100, random_state=42)
   model.fit(X_train, y_train)
   y_pred = model.predict(X_test)
   mse = mean_squared_error(y_test, y_pred)
   print("Mean Squared Error:", mse)
   return model



def packet_size_nn(df):
    """ Trains a Neural Network model for packet size prediction. """
    X_text = df[['Network Protocol', 'Transport Protocol', 'Operation', 'Source']]
    y = df['Packet Size']   
    X_categorical = pd.get_dummies(X_text[[
      'Network Protocol', 'Transport Protocol', 'Operation', 'Source'
    ]])
    X_train, X_test, y_train, y_test = train_test_split(
        X_categorical, y, test_size=0.2, random_state=42
    )
    model = MLPRegressor(
        hidden_layer_sizes=(100,), activation='relu', 
        solver='adam', max_iter=1000, random_state=42
    )
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    mse = mean_squared_error(y_test, y_pred)
    rmse = np.sqrt(mse)
    print("Root Mean Squared Error:", rmse)
    
    return model



def create_source_column(df):
    """ Adding the fantastic 'Source' column """
    sources = []
    for index, row in df.iterrows():
        operation = row['Operation']
        summary = row['Summary'].split()
        if 'Transport' in operation or 'Connection-Transport' in operation:
            if len(summary) >= 3:
                source = summary[2]
                sources.append(source)
            else:
                sources.append('Unknown')
        elif len(summary) >= 5:
            source = summary[4]
            sources.append(source)
        else:
            sources.append('Unknown')
    df['Source'] = sources
    return df


def form_the_df(df):
   """ Forms the Pandas DataFrame for ML models to learn better. """
   df['Network Protocol'] = df['Summary'].str.split().str[0]
   df['Transport Protocol'] = df['Summary'].str.split().str[1]
   df.loc[~df['Transport Protocol'].isin(['TCP', 'UDP']), 'Transport Protocol'] = 'Other'
   
   df['Operation'] = ''
   dns_rows = df[df['Summary'].str.contains('DNS')]
   df.loc[dns_rows.index, 'Operation'] = dns_rows[
      'Summary'].str.split().str[2] + '-' + dns_rows['Summary'].str.split().str[3]
   
   tcp_rows = df[(~df['Summary'].str.contains('DNS')) & (df['Transport Protocol'] == 'TCP')]
   df.loc[tcp_rows.index, 'Operation'] = 'Connection-Transport'
   udp_rows = df[(~df['Summary'].str.contains('DNS')) & (df['Transport Protocol'] == 'UDP')]
   df.loc[udp_rows.index, 'Operation'] = 'Transport'

   df = create_source_column(df)

   return df




def main():
  """ Driver function. """
  df = filter_pcap("output1.pcap")
  # To observe better and reusability
  df = form_the_df(df)
  print(df.head(10))
  #packet_size_lr(df)   
  #packet_size_rf(df)
  packet_size_nn(df)
  df.to_csv("pcap.csv")
  #packet_size_rf2(df)

main()
