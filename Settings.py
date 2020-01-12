# Copyright 2020 @ Agathe Blaise.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator
from collections import OrderedDict
import sys
import os
import socket
import struct
import warnings
import csv
from sklearn import metrics
from sklearn.cluster import DBSCAN
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
warnings.filterwarnings('ignore')

class Dataset:
    def __init__(self, path_file, path_figs):
        self.path_file = path_file
        self.path_figs = path_figs
        self.flowdata = pd.DataFrame()
        self.hosts = []
        self.unique_hosts = []
        self.hosts_study = {}
        self.hosts_proto = {}
        self.bots = []
        self.pairs = []
        
class Protocol():
    def __init__(self, proto, color):
        self.proto = proto
        self.color = color
        
    def get_list(self, out, attribute):
        if 'Addr' in attribute:
            return [ip2int(x) for x in out[self.proto][attribute].tolist()]
        else:
            if self.proto in ['tcp', 'udp']:
                return [int(x) if str(x) != 'nan' else 0 for x in out[self.proto][attribute].tolist()]
            else:
                return [hexa2int(x) for x in out[self.proto][attribute].tolist()]
            
class Attribute():
    def __init__(self, att, label, limit):
        self.att = att
        self.label = label
        self.limit = limit
        
class Cluster:
    bot = False
    ind_cluster = - 1
    hosts = []
    coord = []
    
    def __init__(self, bot, ind_cluster, hosts, coord):
        self.bot = bot
        self.ind_cluster = ind_cluster
        self.hosts = hosts
        self.coord = coord

def ip2int(addr):
    return struct.unpack('!I', socket.inet_aton(addr))[0]

def hexa2int(hexa):
    if str(hexa) == 'nan':
        return 0
    return int(str(hexa), 0)
        
def get_list_hosts(dataset_type, min_pkt_proto):
    list_hosts = []
    for ind_d, dataset in enumerate(datasets):
        if dataset_type == 'training' and ind_d in TRAINING:
            for host in dataset.hosts:
                for p in protocols:
                    if host in dataset.hosts_proto[min_pkt_proto][p.proto]:
                        list_hosts.append(str(ind_d) + '_' + host)
                        break
        elif dataset_type == 'testing' and ind_d not in TRAINING:
            for host in dataset.hosts:
                for p in protocols:
                    if host in dataset.hosts_proto[min_pkt_proto][p.proto]:
                        list_hosts.append(str(ind_d) + '_' + host)
                        break
    return list_hosts

def get_coord_hosts(dataset_type, list_hosts, min_pkt_proto, nb_bin, bins_type, n_top_hosts):
    list_bins, total_hosts = ({} for i in range(2))
    clusters = []
    for id_host in list_hosts:
        ind_d, host = id_host.split('_')
        total_hosts[id_host] = len_dataset[datasets[int(ind_d)]][host]
    od = OrderedDict(sorted(total_hosts.items(), key=lambda x:x[1], reverse=True))
    top_hosts = list(od.keys())
    hosts_todeal = top_hosts[:n_top_hosts] if n_top_hosts != 0 else top_hosts
    for ind_d, dataset in enumerate(datasets):
        if dataset_type == 'training':
            if ind_d in TRAINING:
                for bot in dataset.bots:
                    bot_ip = str(ind_d) + '_' + bot
                    if bot_ip not in hosts_todeal:
                        hosts_todeal.append(bot_ip)
        if dataset_type == 'testing':
            if ind_d not in TRAINING:
                for bot in dataset.bots:
                    bot_ip = str(ind_d) + '_' + bot
                    if bot_ip not in hosts_todeal:
                        hosts_todeal.append(bot_ip)
        
    for id_host in hosts_todeal:
        list_bins[id_host] = []
        ind_d, host = id_host.split('_')
        for p in protocols:
            for a in attributes:
                if host in datasets[int(ind_d)].hosts_proto[min_pkt_proto][p.proto]:
                    if bins_type == 'regular':
                        hist, bin_edges = np.histogram(p.get_list(out_src[datasets[int(ind_d)]][host], a.att),
                                                       bins=nb_bin, range=[0, a.limit], density=True)
                    elif bins_type == 'adaptive':
                        hist, bin_edges = np.histogram(p.get_list(out_src[datasets[int(ind_d)]][host], a.att),
                                                   bins=new_bins[a.label + '_' + p.proto][nb_bin], density=True)
                    hist[np.isnan(hist)] = 0
                else:
                    hist = np.zeros(nb_bin)
                list_bins[id_host].extend(hist)
        if all(x == 0.0 for x in list_bins[id_host]):
            del list_bins[id_host]
    return list_bins

def clustering(list_hosts, min_pkt_proto, nb_bin, bins_type, n_top_hosts, eps):
    list_bins = get_coord_hosts('training', list_hosts, min_pkt_proto, nb_bin, bins_type, n_top_hosts)
    scaler = StandardScaler()
    standard_len = min([len(x) for x in list(list_bins.values())])
    for k, v in list_bins.items():
        if len(v) > standard_len:
            list_bins[k] = list_bins[k][:standard_len]
    scaler.fit(list(list_bins.values()))
    X = scaler.transform(list(list_bins.values()))
    cl = DBSCAN(eps=eps, min_samples=1, metric='l1').fit(X)
    labels = cl.labels_
    clusters = []
        
    add_hosts = 0
    n_bot_clusters = 0
    for head in range(max(labels) + 1):
        hosts = []
        bool_bot = False
        for ind_lab, lab in enumerate(labels):
            if head == lab:
                hosts.append(list(list_bins.keys())[ind_lab])
                ind_d, host = list(list_bins.keys())[ind_lab].split('_')
                if host in datasets[int(ind_d)].bots:
                    bool_bot = True
        cluster_points = [list_bins[host] for host in hosts]
        clusters.append(Cluster(bool_bot, head, hosts, np.mean(cluster_points, axis=0)))
        if bool_bot:
            n_bot_clusters += 1
            for id_host in hosts:
                ind_d, host = id_host.split('_')
                if host not in datasets[int(ind_d)].bots:
                    add_hosts += 1
                    
    silhou = metrics.silhouette_score(X, labels) if len(set(labels)) > 2 else 0
    return list_bins, labels, X, clusters, len(set(labels)), silhou, add_hosts, scaler

def classification(list_hosts, min_pkt_proto, nb_bin, bins_type, coord_clusters, scaler, n_top_hosts):
    bots_wellclassified, normal_misclassified, bots_misclassified, normal_wellclassified = ([] for i in range(4))
    list_bins = get_coord_hosts('testing', list_hosts, min_pkt_proto, nb_bin, bins_type, n_top_hosts)
    for id_host, coord_host in list_bins.items():
        ind_d, host = id_host.split('_')
        distances = {}
        for cluster in coord_clusters:
            if len(cluster.coord) > len(coord_host):
                distances[cluster] = np.linalg.norm(np.array(cluster.coord[:len(coord_host)]) - np.array(coord_host), ord=1)
            elif len(cluster.coord) < len(coord_host):
                distances[cluster] = np.linalg.norm(np.array(cluster.coord) - np.array(coord_host[:len(cluster.coord)]), ord=1)
            elif len(cluster.coord) == len(coord_host):
                distances[cluster] = np.linalg.norm(np.array(cluster.coord) - np.array(coord_host), ord=1)
        
        cluster_closer = min(distances, key=distances.get)
        if cluster_closer.bot:
            list_append = bots_wellclassified if host in datasets[int(ind_d)].bots else normal_misclassified
        else:
            list_append = bots_misclassified if host in datasets[int(ind_d)].bots else normal_wellclassified
        list_append.append(id_host)
    tp = bots_wellclassified
    fn = bots_misclassified
    fp = normal_misclassified
    tn = normal_wellclassified
    precision = float(len(tp)) / len(tp + fp) if len(tp + fp) != 0 else 0
    recall = float(len(tp)) / len(tp + fn) if len(tp + fn) != 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if precision + recall != 0 else 0
    return precision, recall, f1_score

def full_process(list_hosts_tr, list_hosts_te, min_pkt_proto, nb_bin, bins_type, density):
    n_top_hosts = 0
    list_bins_tr = get_coord_hosts('training', hosts_training[param], param, nb_bin, bins_type, density)
    list_bins_te = get_coord_hosts('testing', hosts_testing[param], param, nb_bin, bins_type, density)
    standard_len = min([len(x) for x in list(list_bins_tr.values())])
    for k, v in list_bins_tr.items():
        list_bins_tr[k] = list_bins_tr[k][:standard_len]
    for k, v in list_bins_te.items():
        list_bins_te[k] = list_bins_te[k][:standard_len]
                
    X_train = list(list_bins_tr.values())
    X_test = list(list_bins_te.values())
    Y_train, Y_test = ([] for i in range(2))
    for id_host in list(list_bins_tr.keys()):
        ind_d, host = id_host.split('_')
        if host in datasets[int(ind_d)].bots:
            Y_train.append('bot')
        else:
            Y_train.append('benign')
            
    for id_host in list(list_bins_te.keys()):
        ind_d, host = id_host.split('_')
        if host in datasets[int(ind_d)].bots:
            Y_test.append('bot')
        else:
            Y_test.append('benign')
    
    sc = StandardScaler()
    X_train = sc.fit_transform(X_train)
    X_test = sc.transform(X_test)
    return X_train, Y_train, X_test, Y_test
        
MAIN_PATH = '/Users/agatheblaise/CTU-13-Dataset/'
IP_BOTNET = '147.32.84.165'
MIN_PKT_PROTO = 150
EPSILONS = range(1, 511, 30)
TRAINING = [2, 3, 4, 6, 9, 10, 11, 12]
ATT = ['Sport', 'Dport', 'Proto', 'Label', 'SrcAddr', 'DstAddr', 'StartTime']
NB_BINS_VARY = [8, 16, 32, 64, 128, 256, 512, 1024]
PERS = np.arange(0.1, 1.1, 0.1)
BINS_TYPES = ['adaptive', 'regular']  


protocols = [Protocol('tcp', 'b'), Protocol('udp', 'g'), Protocol('icmp', 'r')]
attributes = [Attribute('Sport', 'sport', 65536),
              Attribute('Dport', 'dport', 65536),
              Attribute('DstAddr', 'dip', 2 ** 32)]
