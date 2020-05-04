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

from Settings import *

def initialisation():
    scenarios = []
    cap_files = [MAIN_PATH + str(d) for d in range(1, 14)]
    for f in cap_files:
        binetflow_file = next(x for x in os.listdir(f) if 'binetflow' in x)
        scen = Scenario(f + '/' + binetflow_file)
        frame = pd.read_csv(f + '/' + binetflow_file, header=0)

        # flowdata is a pandas Dataframe containing all flows from a given scenario
        # it is a column-based representation to handle data
        scen.flowdata = scen.flowdata.append(frame, ignore_index=True)
        scen.flowdata.rename(columns=lambda x: x.strip(), inplace = True)

        # append to scen.hosts all unique source IP addresses in 147.32.X.X (internal network)
        hosts = scen.flowdata['SrcAddr'].unique()
        scen.hosts = [x for x in hosts if '147.32.' in x]

        # append to scen.bots all malicious source IP addresses in 147.32.X.X (internal network)
        bots = scen.flowdata[scen.flowdata['Label'].str.contains('Botnet')]['SrcAddr'].unique()
        scen.bots = [x for x in bots if '147.32' in x]

        scenarios.append(scen)

    # define dictionary containing all packets taken by a particular host from a scenario for a given protocol
    # e.g. packets[scen1][host1]['TCP'] contain all TCP packets from host1 from scenario1
    # we will compute the frequency distributions of such value later, to build the hosts signatures
    packets = {}
    for scen in scenarios:
        packets[scen] = {}
        for host in scen.hosts:
            packets[scen][host] = {}
            flows = scen.flowdata.loc[scen.flowdata.SrcAddr == host]
            for p in protocols:
                packets[scen][host][p.proto] = flows.loc[:, ATT].loc[flows.Proto == p.proto]
                if not packets[scen][host][p.proto].empty:
                    packets[scen][host][p.proto] = packets[scen][host][p.proto].fillna(0)

    # for each protocol, store the list of hosts with at least MIN_PKT_PROTO packets
    # e.g. for scenario1 and TCP, keep the list of hosts with at least MIN_PKT_PROTO TCP packets
    for ind_scen, scen in enumerate(scenarios):
        scen.hosts_proto = {}
        for p in protocols:
            scen.hosts_proto[p.proto] = []
            for host in scen.hosts:
                if len(p.get_list(packets[scen][host], 'Sport')) >= MIN_PKT_PROTO:
                    scen.hosts_proto[p.proto].append(host)

    hosts_training, hosts_test = ([] for i in range(2))
    for ind_scen, scen in enumerate(scenarios):
        if ind_scen in TRAINING:
            hosts_training.extend([str(ind_scen) + '_' + x for x in list(set(scen.hosts_proto['tcp'] + scen.hosts_proto['udp'] + scen.hosts_proto['icmp'] + scen.bots))])
        else:
            hosts_test.extend([str(ind_scen) + '_' + x for x in list(set(scen.hosts_proto['tcp'] + scen.hosts_proto['udp'] + scen.hosts_proto['icmp']  + scen.bots))])

    return scenarios, packets, hosts_training, hosts_test
                
def define_adaptive_bins():
    ad_bins, vectors = ({} for i in range(2))

    with open('vectors.csv', 'r') as csv_file:
        read_csv = csv.reader(csv_file, delimiter=';')
        for row in read_csv:
            vectors[row[0]] = [int(x) for x in row[1][1:-1].split(',')]

    for p in protocols:
        for a in attributes:
            # feature in [Sport_TCP, Dport_TCP, Dip_TCP, Sport_UDP, Dport_UDP, Dip_UDP, Sport_ICMP, Dport_ICMP, Dip_ICMP]
            feature = a.label + '_' + p.proto
            ad_bins[feature] = {}
            step = a.limit / 1000 # e.g. for source port, divide the maximum (65,536) into 1,000 bins and compute number of different ports for each bin
            # e.g. in the range [0, 1023]: a lot of different destination port numbers but small different source port numbers
            bin_edges = np.arange(0, a.limit, step)
            cumsum = np.cumsum(vectors[feature]) # vectors.csv contains the number of unique elements in each of the 1,000 bins, for each feature
            cumsum = np.insert(cumsum, 0, 0.0) # add 0 for the first bin, to get the right number of values

            # then here, form nb_bin bins (e.g. 32 bins) so that there is the same number of ports in each bin
            # the bins will then have an adaptive width depending on the amount of information
            for nb_bin in NB_BINS_VARY:
                ad_bins[feature][nb_bin] = []
                step = max(cumsum) / nb_bin
                new_y = np.arange(0, max(cumsum), step)
                for el in new_y:
                    for index in range(len(cumsum) - 1):
                        if cumsum[index] <= el < cumsum[index+1]:
                            ad_bins[feature][nb_bin].append(bin_edges[index])

    return ad_bins

def botFP_clus(packets, scenarios, hosts_training, hosts_test, ad_bins):
    signatures, coord_clusters, nb_clusters, tpr, fpr, accuracy = ({} for i in range(6))
    for nb_bin in NB_BINS_VARY:
        for bin_type in BINS_TYPES:
            id = '_'.join([str(MIN_PKT_PROTO), str(nb_bin), bin_type])
            signatures[id], coord_clusters[id], nb_clusters[id], tpr[id], fpr[id], accuracy[id] = ({} for i in range(6))
            for eps in EPSILONS:
                # clustering = learning
                coord_clusters[id][eps], nb_clusters[id][eps] = clustering(packets, scenarios, hosts_training, MIN_PKT_PROTO, nb_bin, bin_type, eps, ad_bins)

                # classification = evaluation
                tpr[id][eps], fpr[id][eps], accuracy[id][eps] = classification(packets, scenarios, hosts_test, MIN_PKT_PROTO, nb_bin, bin_type, coord_clusters[id][eps], ad_bins)
    return tpr, fpr, accuracy, nb_clusters

def plot_figure(metric, metric_values):
    FONT_SIZE = 15
    LABEL_SIZE = 12

    # plot figure for regular and adaptive bins
    for bins_type in BINS_TYPES:
        fig, ax = plt.subplots(figsize=(5, 4.5), dpi=400)
        for ind_param, nb_bin in enumerate(NB_BINS_VARY):
            id = '_'.join([str(MIN_PKT_PROTO), str(nb_bin), bins_type])
            ax.plot(EPSILONS, metric_values[id][x],  label= r'$b =%d$' % (nb_bin), marker=MARKERS[ind_param], ls=LINE_STYLES[ind_param], markersize=8, linewidth=2)
        
        ax.tick_params(axis='both', which='major', labelsize=LABEL_SIZE)
        ax.set_ylim(-0.05, 1.05)
        ax.legend(loc='lower center', bbox_to_anchor=(0.47, 1), shadow=True, ncol=3, fontsize=LABEL_SIZE)
        ax.set_xlabel(r'$\epsilon$', fontsize= FONT_SIZE)
        ax.set_xticklabels(EPSILONS)

        fig.tight_layout()
        fig.savefig(metric + '_' + bins_type + '.png')

def main(argv):
    scenarios, packets, hosts_training, hosts_test = initialisation()
    ad_bins = define_adaptive_bins()
    tpr_clusters, fpr_clusters, accuracy, nb_clusters = botFP_clus(packets, scenarios, hosts_training, hosts_test, ad_bins)
    print(tpr_clusters, fpr_clusters, accuracy, nb_clusters)

    # for tuning: change parameters in Settings.py and run this code
    # tpr_clusters, fpr_clusters, accuracy, nb_clusters = botFP_clus(packets, scenarios, hosts_training, hosts_test, ad_bins)
    # print(tpr_clusters, fpr_clusters, accuracy, nb_clusters)
    # for metric, metric_values in {'tpr': tpr_cl, 'fpr': fpr_cl, 'nb_clusters': n_clusters}:
    #     plot_figure(metric, metric_values)

    return 0

if __name__ == '__main__':
    main(sys.argv)
