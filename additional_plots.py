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
from detection import initialisation

# merge all datasets and draw histograms of nb of pkts per protocol
def hist_parameter_m(per, scenarios, packets, list_hosts):
    for p in protocols:
        fig, ax = plt.subplots()
        scenario_hosts = [int(host.split('_')[0]) for host in list_hosts] # hosts from scenario 0
        name_hosts = [host.split('_')[1] for host in list_hosts]
        nbs = {host: packets[scenarios[scenario_hosts[i]]][name_hosts[i]][p.proto].shape[0] for i, host in enumerate(list_hosts)}
        nbs_sorted = list(nbs.values())
        nbs_sorted.sort()
        nbs_sorted = nbs_sorted[:int(per / 100 * len(nbs_sorted))]
        counts, bins = np.histogram(nbs_sorted, bins=20)
        for item in range(len(bins) - 1):
            hosts = [host for host, value in nbs.items() if bins[item] < value < bins[item + 1]]
        ax.hist(bins[:-1], bins, weights=counts, log=True)
        ax.set_xlabel('number of packets for proto ' + p.proto)
        ax.set_ylabel('occurrence')
        ax.xaxis.set_major_locator(MaxNLocator(integer=True))
        print(counts)
        fig.savefig('hist_' + p.proto + '_' + per + '%.png', dpi=400)

def overview_graph(host, packets):
    scenario = scenarios[0]
    FONT_SIZE = 13

    fig = plt.figure(figsize=(15, 7), dpi=400)
    ax = fig.add_subplot(1, 3, 1)
    for p in protocols:
        if p.proto == 'tcp':
            legend = 'TCP'
        if p.proto == 'udp':
            legend = 'UDP'
        if p.proto == 'icmp':
            legend = 'ICMP'
        im = ax.scatter(p.get_list(packets[scenario][host], 'Sport'),
                     p.get_list(packets[scenario][host], 'Dport'), alpha=0.3, color=p.color, marker='o', label=legend)

    ax.set_xlim(0, 65536)
    ax.set_ylim(0, 65536)
    ax.legend()
    ax.set_xlabel('srcPort', fontsize=FONT_SIZE)
    ax.set_ylabel('dstPort', fontsize=FONT_SIZE)

    ax = fig.add_subplot(1, 3, 2)
    for p in protocols:
        im = ax.scatter(p.get_list(packets[scenario][host], 'Sport'),
                     p.get_list(packets[scenario][host], 'DstAddr'), color=p.color, marker='o')
    ax.set_xlim(0, 65536)
    ax.set_ylim(0, 2 ** 32)
    ax.set_xlabel('srcPort', fontsize=FONT_SIZE)
    ax.set_ylabel('dstIP', fontsize=FONT_SIZE)

    ax = fig.add_subplot(1, 3, 3)
    im = ax.scatter(p.get_list(packets[scenario][host], 'Dport'),
                 p.get_list(packets[scenario][host], 'DstAddr'), color=p.color, marker='o')
    ax.set_xlim(0, 65536)
    ax.set_ylim(0, 2 ** 32)
    ax.set_xlabel('dstPort', fontsize=FONT_SIZE)
    ax.set_ylabel('dstIP', fontsize=FONT_SIZE)

    fig.savefig('host_benign.png')

def comparison_two_hosts(packets):
    scenario = scenarios[0]
    FONT_SIZE = 16
    N_BINS = 32
    WIDTH = 0

    titles = [r'$srcPort_{TCP}$', r'$dstPort_{UDP}$', r'$dstIP_{UDP}$']
    features = [[Protocol('tcp', 'b'), Attribute('Sport', 'sport', 65536)],
                [Protocol('udp', 'g'), Attribute('Dport', 'dport', 65536)],
                [Protocol('udp', 'g'), Attribute('DstAddr', 'dip', 2 ** 32)]]

    fig = plt.figure(figsize=(10, 10), dpi=400)

    ids = ['0_147.32.84.17', '0_147.32.84.165']

    for ind_h, id_host in enumerate(ids):
        for ind_feat, feat in enumerate(features):
            ax = fig.add_subplot(3, 2, 1 + ind_h + 2 * ind_feat)
            ind_s, host = id_host.split('_')
            p, a = feat[:]
            hist, bin_edges = np.histogram(p.get_list(packets[scenarios[int(ind_s)]][host], a.att),
                                            bins=N_BINS, range=[0, a. limit], density=True)
            if a.label == 'sport' or a.label == 'dport':
                WIDTH = 2048
            else: WIDTH = 134217728
            color = 'b' if id_host == '0_147.32.84.17' else 'r'
            if ind_feat == 0 or ind_feat == 1:
                ax.set_xticks([0, 20000, 40000, 60000])
                ax.set_xticklabels([0, 20000, 40000, 60000])
            if ind_feat == 0:
                ax.set_ylim([0, 0.00025])
                ax.set_yticklabels(['0.0000', '0.0005', '0.0010', '0.0015', '0.0020', '0.0025'])
            if ind_feat == 1:
                ax.set_yticklabels(['0.000', '0.001', '0.002', '0.003', '0.004', '0.005'])
            if ind_feat == 2:
                ax.set_ylim([0, 8 * 10**-9])
            ax.bar(bin_edges[:-1], hist, width=WIDTH, color=color)
            ax.tick_params(axis='both', labelsize=13)
            ax.set_xlabel(titles[ind_feat], fontsize=FONT_SIZE)
            ax.set_ylabel('frequency distribution', fontsize=FONT_SIZE)
    fig.tight_layout()
    fig.savefig('hist.png', dpi=400)

def main(argv):
    scenarios, packets, hosts_training, hosts_test = initialisation()

    per = 70 # representing the 70% smallest hosts
    hist_parameter_m(per, scenarios, packets, hosts_training)

    overview_graph('147.32.84.17', packets) # '147.32.84.17' for benign host, '147.32.84.165' for bot
    overview_graph('147.32.84.165', packets)

    comparison_two_hosts(packets)
    return 0

if __name__ == '__main__':
    main(sys.argv)