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
import sys
import os
import socket
import struct
import warnings
import csv
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from matplotlib.ticker import MaxNLocator

warnings.filterwarnings('ignore')

class Scenario:
    def __init__(self, path_file):
        self.path_file = path_file
        self.flowdata = pd.DataFrame()
        self.hosts = []
        self.bots = []
        self.hosts_proto = {}
        
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
    hosts = []
    coord = []
    
    def __init__(self, bot, hosts, coord):
        self.bot = bot
        self.hosts = hosts
        self.coord = coord

# convert the IP into an integer, e.g. IP 255.255.255.255 = 255*(256^3) + 255*(256^2) + 255*256 + 255 = 4294967295
def ip2int(addr):
    return struct.unpack('!I', socket.inet_aton(addr))[0]

# convert a hexadecimal number (e.g. for ICMP) to an integer file
def hexa2int(hexa):
    if str(hexa) == 'nan':
        return 0
    return int(str(hexa), 0)

def compute_hosts_signatures(packets, scenarios, list_hosts, min_pkt_proto, nb_bin, bins_type, ad_bins):
    signatures = {}
        
    for id_host in list_hosts:
        signatures[id_host] = []
        ind_scen, host = id_host.split('_')
        for p in protocols:
            for a in attributes:
                if host in scenarios[int(ind_scen)].hosts_proto[p.proto]:
                    if bins_type == 'regular':
                        hist, bin_edges = np.histogram(p.get_list(packets[scenarios[int(ind_scen)]][host], a.att),
                                                       bins=nb_bin, range=[0, a.limit], density=True)
                    elif bins_type == 'adaptive':
                        hist, bin_edges = np.histogram(p.get_list(packets[scenarios[int(ind_scen)]][host], a.att),
                                                   bins=ad_bins[a.label + '_' + p.proto][nb_bin], density=True)
                    # replace eventual NaN values by 0
                    hist[np.isnan(hist)] = 0
                else:
                    # if the host contains less than MIN_PKT_PROTO packets for the given protocol, we do not compute the frequency distribution
                    # but we replace it by a list containg only 0 values ([0, 0, .., 0])
                    hist = np.zeros(nb_bin)
                
                signatures[id_host].extend(hist)

        # # if all signatures are made from [0, 0, .., 0], i.e. less than MIN_PKT_PROTO packets for all protocols, we discard the host
        # if all(x == 0.0 for x in signatures[id_host]):
        #     del signatures[id_host]

    return signatures

def clustering(packets, scenarios, list_hosts, min_pkt_proto, nb_bin, bins_type, eps, ad_bins):
    signatures = compute_hosts_signatures(packets, scenarios, list_hosts, min_pkt_proto, nb_bin, bins_type, ad_bins)

    # enables to standardize length if host coordinates contain 1 or 2 more bins than usual
    standard_len = min([len(x) for x in list(signatures.values())])
    signatures = dict((k, v[:standard_len] if len(v) > standard_len else v) for k, v in signatures.items())

    X = StandardScaler().fit_transform(list(signatures.values()))
    cl = DBSCAN(eps=eps, min_samples=1, metric='l1').fit(X)

    # we get a list of clusters IDs
    # e.g. [0, 0, 1, 2, 1, 1] means that the first 2 points belong to cluster 0, the 3rd and 2 last points to cluster 1, and the 4th to cluster 2
    labels = cl.labels_
    clusters = []
    
    # head is the id of the cluster; so for each unique cluster id:
    for head in range(max(labels) + 1):
        hosts = []
        bool_bot = False
        for ind_lab, lab in enumerate(labels):
            if head == lab:
                hosts.append(list(signatures.keys())[ind_lab])
                ind_scen, host = list(signatures.keys())[ind_lab].split('_')

                # if the cluster contains at least one bot, thus the cluster is labelled as bot (i.e. bool_bot = True)
                if host in scenarios[int(ind_scen)].bots:
                    bool_bot = True

        cluster_coordinates = [signatures[host] for host in hosts]

        # the coordinates of the cluster is the barycenter of the coordinates of all the hosts it contains
        barycentre = np.mean(cluster_coordinates, axis=0)
        clusters.append(Cluster(bool_bot, hosts, barycentre))
                    
    return clusters, len(set(labels))

def classification(packets, scenarios, list_hosts, min_pkt_proto, nb_bin, bins_type, coord_clusters, ad_bins):
    tp, fp, tn, fn = ([] for i in range(4))

    signatures = compute_hosts_signatures(packets, scenarios, list_hosts, min_pkt_proto, nb_bin, bins_type, ad_bins)
    for id_host, coord_host in signatures.items():
        ind_scen, host = id_host.split('_')
        distances = {}
        for cluster in coord_clusters:

            # standardize length because once again, one signature can contain one or two more bins than the other one
            standard_len = min([len(x) for x in [cluster.coord, coord_host]])
            cluster.coord = cluster.coord[:standard_len]
            coord_host = coord_host[:standard_len]

            distances[cluster] = np.linalg.norm(np.array(cluster.coord) - np.array(coord_host), ord=1)
        
        closest_cluster = min(distances, key=distances.get)

        # if the closest cluster is a bot
        if closest_cluster.bot:
            # and the host was really a bot, then it is a true positive
            if host in scenarios[int(ind_scen)].bots:
                tp.append(id_host)
            # but the host was in fact benign, then it is a false positive
            else:
                fp.append(id_host)
        # if the closest cluster is benign
        else:
            # but the host was a bot, then it is a false negative
            if host in scenarios[int(ind_scen)].bots:
                fn.append(id_host)
            # and the host was really benign, then it is a true negative
            else:
                tn.append(id_host)

    tpr = float(len(tp)) / len(tp + fn) if len(tp + fn) != 0 else 0
    fpr = float(len(fp)) / len(tn + fp) if len(tn + fp) != 0 else 0
    accuracy = float(len(tp + tn)) / len(tp + tn + fp + fn) if len(tp + tn + fp + fn) != 0 else 0

    return tpr, fpr, accuracy
        
MAIN_PATH = '/Users/agatheblaise/CTU-13-Dataset/'
IP_BOTNET = '147.32.84.165'
MIN_PKT_PROTO = 150
TRAINING = [2, 3, 4, 6, 9, 10, 11, 12]
ATT = ['Sport', 'Dport', 'Proto', 'Label', 'SrcAddr', 'DstAddr']
LINE_STYLES = ['--', '-.', ':', '-', '-.', ':', '--', '-.']
MARKERS = ['o', 'v', '^', 'p', 's', '*', 's', 'p', '*', 'h', 'H', 'D', 'd', 'P', 'X']

# parameters for tuning
# BINS_TYPES = ['adaptive', 'regular']
# NB_BINS_VARY = [8, 16, 32, 64, 128, 256, 512, 1024]
# EPSILONS = range(1, 511, 30)

# best parameters
BINS_TYPES = ['adaptive']
NB_BINS_VARY = [512]
EPSILONS = [300]


protocols = [Protocol('tcp', 'b'), Protocol('udp', 'g'), Protocol('icmp', 'r')]
attributes = [Attribute('Sport', 'sport', 65536),
              Attribute('Dport', 'dport', 65536),
              Attribute('DstAddr', 'dip', 2 ** 32)]
