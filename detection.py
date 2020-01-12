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

def init():
    datasets = []
    cap_files = [MAIN_PATH + str(d) for d in range(1, 14)]
    for f in cap_files:
        file = next(x for x in os.listdir(f) if 'binetflow' in x)
        dataset = Dataset(f + '/' + file, f + '/figs/')
        frame = pd.read_csv(f + '/' + file, header=0)
        dataset.flowdata = dataset.flowdata.append(frame, ignore_index=True)
        dataset.flowdata.rename(columns=lambda x: x.strip(), inplace = True)
        dataset.unique_hosts = dataset.flowdata['SrcAddr'].unique()
        dataset.hosts = [x for x in dataset.unique_hosts if '147.32.' in x]
        temp_bots = dataset.flowdata[dataset.flowdata['Label'].str.contains('Botnet')]['SrcAddr'].unique()
        dataset.bots = [x for x in temp_bots if '147.32' in x]
        datasets.append(dataset)

    out_src = {}
    out_dst = {}
    for dataset in datasets:
        out_src[dataset] = {}
        out_dst[dataset] = {}
        for host in dataset.hosts:
            out_src[dataset][host] = {}
            out_dst[dataset][host] = {}
            host_flows_src = dataset.flowdata.loc[dataset.flowdata.SrcAddr == host]
            host_flows_dst = dataset.flowdata.loc[dataset.flowdata.DstAddr == host]
            for p in protocols:
                out_src[dataset][host][p.proto] = host_flows_src.loc[:, ATT].loc[host_flows_src.Proto == p.proto]
                out_dst[dataset][host][p.proto] = host_flows_dst.loc[:, ATT].loc[host_flows_dst.Proto == p.proto]
                if not out_src[dataset][host][p.proto].empty and not out_dst[dataset][host][p.proto].empty:
                    out_src[dataset][host][p.proto] = out_src[dataset][host][p.proto].fillna(0)
                    out_dst[dataset][host][p.proto] = out_dst[dataset][host][p.proto].fillna(0)           

    for dataset in datasets:
        dataset.hosts_proto[MIN_PKT_PROTO] = {}
        for p in protocols:
            dataset.hosts_proto[MIN_PKT_PROTO][p.proto] = []
            for host in dataset.hosts:
                len_dataset2 = len(p.get_list(out_src[dataset][host], 'Sport'))
                if len_dataset2 >= MIN_PKT_PROTO:
                    dataset.hosts_proto[MIN_PKT_PROTO][p.proto].append(host)
                        
    len_dataset = {}
    for dataset in datasets:
        len_dataset[dataset] = {}
        for host in dataset.hosts:
            len_dataset[dataset][host] = 0
            for p in protocols:
                len_dataset[dataset][host] += len(p.get_list(out_src[dataset][host], 'Sport'))
                
    vectors, new_bins = ({} for i in range(2))
    with open('vectors.csv', 'r') as csv_file:
        read_csv = csv.reader(csv_file, delimiter=';')
        for row in read_csv:
            vectors[row[0]] = [int(x) for x in row[1][1:-1].split(',')]
        
    new_bins = {}
    for p in protocols:
        for a in attributes:
            feat = a.label + '_' + p.proto
            new_bins[feat] = {}
            step = a.limit / 1000
            bin_edges = np.arange(0, a.limit, step)
            cumsum = np.cumsum(vectors[feat])
            cumsum = np.insert(cumsum, 0, 0.0)
            for nb_bin in nb_bin_vary:
                new_bins[feat][nb_bin] = []
                step = max(cumsum) / nb_bin
                new_y = np.arange(0, max(cumsum), step)
                for el in new_y:
                    for index in range(len(cumsum) - 1):
                        if cumsum[index] <= el < cumsum[index+1]:
                            new_bins[feat][nb_bin].append(bin_edges[index])

def define_adaptive_bins():
    new_bins = {}
    for p in protocols:
        for a in attributes:
            feat = a.label + '_' + p.proto
            new_bins[feat] = {}
            step = a.limit / 1000
            bin_edges = np.arange(0, a.limit, step)
            cumsum = np.cumsum(vectors[feat])
            cumsum = np.insert(cumsum, 0, 0.0)
            for nb_bin in NB_BINS_VARY:
                new_bins[feat][nb_bin] = []
                step = max(cumsum) / nb_bin
                new_y = np.arange(0, max(cumsum), step)
                for el in new_y:
                    for index in range(len(cumsum) - 1):
                        if cumsum[index] <= el < cumsum[index+1]:
                            new_bins[feat][nb_bin].append(bin_edges[index])

def botFP_clus():
    tpr_cl, fpr_cl = ({} for i in range(2))
    hosts_training, hosts_testing, list_bins, labels, res, coord_clusters, tp, tn, fp, fn, tp_d, tn_d, fp_d, fn_d = ({} for i in range(14))
    hosts_training[MIN_PKT_PROTO] = get_list_hosts('training', MIN_PKT_PROTO)
    hosts_testing[MIN_PKT_PROTO] = get_list_hosts('testing', MIN_PKT_PROTO)
    for nb_bin in NB_BINS_VARY:
        for bin_type in BINS_TYPES:
            id = '_'.join([str(MIN_PKT_PROTO), str(nb_bin), bin_type])
            list_bins[id], labels[id], res[id], coord_clusters[id], tpr_cl[id], fpr_cl[id] = ({} for i in range(6))
            tp[id], fn[id], fp[id], tn[id], tp_d[id], fn_d[id], fp_d[id], tn_d[id] = ({} for i in range(8))
            for eps in EPSILONS:
                list_bins[id][eps], labels[id][eps], res[id][eps], coord_clusters[id][eps], labels[id][eps], silhou, add_hosts, scaler = clustering(hosts_training[MIN_PKT_PROTO], MIN_PKT_PROTO, nb_bin, bin_type, 0, eps)
                tp[id][eps], fn[id][eps], fp[id][eps], tn[id][eps], tp_d[id][eps], fn_d[id][eps], fp_d[id][eps], tn_d[id][eps], tpr_cl[id][eps], fpr_cl[id][eps] = classification(hosts_testing[MIN_PKT_PROTO], MIN_PKT_PROTO, nb_bin, bin_type, coord_clusters[id][eps], scaler, 0)
    return tpr_cl, fpr_cl

def fig_precision():
    FONT_SIZE = 15
    LABEL_SIZE = 12
    fig_reg, ax_reg = plt.subplots(figsize=(5, 4.5))
    fig_ad, ax_ad = plt.subplots(figsize=(5, 4.5))
    line_styles = ['--', '-.', ':', '-', '-.', ':', '--', '-.']
    markers = ['o', 'v', '^', 'p', 's', '*', 's', 'p', '*', 'h', 'H', 'D', 'd', 'P', 'X']

    for ind_param, nb_bin in enumerate(NB_BINS_VARY):
        id = '_'.join([str(MIN_PKT_PROTO), str(nb_bin), 'regular'])
        list_acc = [precision_per[id][x] for x in PERS]
        ax_reg.plot(PERS, list_acc,  label= r'$b =%d$' % (nb_bin), marker=markers[ind_param], ls=line_styles[ind_param], markersize=8, linewidth=2)
        
    ax_reg.tick_params(axis='both', which='major', labelsize=LABEL_SIZE)
    ax_reg.set_ylim(-0.05, 1.05)
    ax_reg.legend(loc='lower center', bbox_to_anchor=(0.47, 1), shadow=True, ncol=3, fontsize=FONT_SIZE-3)
    ax_reg.set_xlabel(r'$\epsilon$', fontsize= FONT_SIZE)
    ax_reg.set_xticklabels([r'0', r'0.2b', '0.4b', '0.6b', '0.8b', 'b'])

    fig_reg.tight_layout()
    fig_reg.savefig('precision_regular_per.png', dpi=400)

    for ind_param, nb_bin in enumerate(NB_BINS_VARY):
        id = '_'.join([str(MIN_PKT_PROTO), str(nb_bin), 'adaptive'])
        list_acc = [precision_per[id][x] for x in PERS]
        ax_ad.plot(PERS, list_acc,  label= r'$b =%d$' % (nb_bin), marker=markers[ind_param], ls=line_styles[ind_param], markersize=8, linewidth=2)

    ax_ad.tick_params(axis='both', which='major', labelsize=LABEL_SIZE)
    ax_ad.legend(loc='lower center', bbox_to_anchor=(0.47, 1), shadow=True, ncol=3, fontsize=FONT_SIZE-3)
    ax_ad.set_ylim(-0.05, 1.05)
    ax_ad.set_xlabel(r'$\epsilon$', fontsize= FONT_SIZE)
    ax_ad.set_xticklabels([r'0', r'0.2b', '0.4b', '0.6b', '0.8b', 'b'])

    fig_ad.tight_layout()
    fig_ad.savefig('precision_adaptive_per.png', dpi=400)

def fig_recall():
    FONT_SIZE = 15
    LABEL_SIZE = 12
    fig_reg, ax_reg = plt.subplots(figsize=(5, 4.5))
    fig_ad, ax_ad = plt.subplots(figsize=(5, 4.5))
    line_styles = ['--', '-.', ':', '-', '-.', ':', '--', '-.']
    markers = ['o', 'v', '^', 'p', 's', '*', 's', 'p', '*', 'h', 'H', 'D', 'd', 'P', 'X']

    for ind_param, nb_bin in enumerate(NB_BINS_VARY):
        id = '_'.join([str(MIN_PKT_PROTO), str(nb_bin), 'regular'])
        list_acc = [recall_per[id][x] for x in PERS]
        ax_reg.plot(PERS, list_acc,  label= r'$b =%d$' % (nb_bin), marker=markers[ind_param], ls=line_styles[ind_param], markersize=8, linewidth=2)
        
    ax_reg.tick_params(axis='both', which='major', labelsize=LABEL_SIZE)
    ax_reg.set_ylim(-0.05, 1.05)
    ax_reg.legend(loc='lower center', bbox_to_anchor=(0.47, 1), shadow=True, ncol=3, fontsize=FONT_SIZE-3)
    ax_reg.set_xlabel(r'$\epsilon$', fontsize= FONT_SIZE)
    ax_reg.set_xticklabels([r'0', r'0.2b', '0.4b', '0.6b', '0.8b', 'b'])

    fig_reg.tight_layout()
    fig_reg.savefig('recall_regular_per.png', dpi=400)

    for ind_param, nb_bin in enumerate(NB_BINS_VARY):
        id = '_'.join([str(MIN_PKT_PROTO), str(nb_bin), 'adaptive'])
        list_acc = [recall_per[id][x] for x in PERS]
        ax_ad.plot(PERS, list_acc,  label= r'$b =%d$' % (nb_bin), marker=markers[ind_param], ls=line_styles[ind_param], markersize=8, linewidth=2)

    ax_ad.tick_params(axis='both', which='major', labelsize=LABEL_SIZE)
    ax_ad.legend(loc='lower center', bbox_to_anchor=(0.47, 1), shadow=True, ncol=3, fontsize=FONT_SIZE-3)
    ax_ad.set_ylim(-0.05, 1.05)
    ax_ad.set_xlabel(r'$\epsilon$', fontsize= FONT_SIZE)
    ax_ad.set_xticklabels([r'0', r'0.2b', '0.4b', '0.6b', '0.8b', 'b'])

    fig_ad.tight_layout()
    fig_ad.savefig('recall_adaptive_per.png', dpi=400)

def fig_f1_score():
    FONT_SIZE = 15
    LABEL_SIZE = 12
    fig_reg, ax_reg = plt.subplots(figsize=(5, 4.5))
    fig_ad, ax_ad = plt.subplots(figsize=(5, 4.5))
    line_styles = ['--', '-.', ':', '-', '-.', ':', '--', '-.']
    markers = ['o', 'v', '^', 'p', 's', '*', 's', 'p', '*', 'h', 'H', 'D', 'd', 'P', 'X']

    for ind_param, nb_bin in enumerate(NB_BINS_VARY):
        id = '_'.join([str(MIN_PKT_PROTO), str(nb_bin), 'regular'])
        list_acc = [f1_score_per[id][x] for x in PERS]
        ax_reg.plot(PERS, list_acc,  label= r'$b =%d$' % (nb_bin), marker=markers[ind_param], ls=line_styles[ind_param], markersize=8, linewidth=2)
        
    ax_reg.tick_params(axis='both', which='major', labelsize=LABEL_SIZE)
    ax_reg.set_ylim(-0.05, 1.05)
    ax_reg.legend(loc='lower center', bbox_to_anchor=(0.47, 1), shadow=True, ncol=3, fontsize=FONT_SIZE-3)
    ax_reg.set_xlabel(r'$\epsilon$', fontsize= FONT_SIZE)
    ax_reg.set_xticklabels([r'0', r'0.2b', '0.4b', '0.6b', '0.8b', 'b'])

    fig_reg.tight_layout()
    fig_reg.savefig('f1_score_regular_per.png', dpi=400)

    for ind_param, nb_bin in enumerate(NB_BINS_VARY):
        id = '_'.join([str(MIN_PKT_PROTO), str(nb_bin), 'adaptive'])
        list_acc = [f1_score_per[id][x] for x in PERS]
        ax_ad.plot(PERS, list_acc,  label= r'$b =%d$' % (nb_bin), marker=markers[ind_param], ls=line_styles[ind_param], markersize=8, linewidth=2)

    ax_ad.tick_params(axis='both', which='major', labelsize=LABEL_SIZE)
    ax_ad.legend(loc='lower center', bbox_to_anchor=(0.47, 1), shadow=True, ncol=3, fontsize=FONT_SIZE-3)
    ax_ad.set_ylim(-0.05, 1.05)
    ax_ad.set_xlabel(r'$\epsilon$', fontsize= FONT_SIZE)
    ax_ad.set_xticklabels([r'0', r'0.2b', '0.4b', '0.6b', '0.8b', 'b'])

    fig_ad.tight_layout()
    fig_ad.savefig('f1_score_adaptive_per.png', dpi=400)

def fig_n_clusters():
    FONT_SIZE = 15
    LABEL_SIZE = 12
    fig_reg, ax_reg = plt.subplots(figsize=(5, 4.5))
    fig_ad, ax_ad = plt.subplots(figsize=(5, 4.5))
    line_styles = ['--', '-.', ':', '-', '-.', ':', '--', '-.']
    markers = ['o', 'v', '^', 'p', 's', '*', 's', 'p', '*', 'h', 'H', 'D', 'd', 'P', 'X']

    for ind_param, nb_bin in enumerate(NB_BINS_VARY):
        id = '_'.join([str(MIN_PKT_PROTO), str(nb_bin), 'regular'])
        list_acc = [n_clusters[id][x] for x in pers]
        ax_reg.plot(pers, list_acc,  label= r'$b =%d$' % (nb_bin), marker=markers[ind_param], ls=line_styles[ind_param], markersize=8, linewidth=2)
        
    ax_reg.tick_params(axis='both', which='major', labelsize=LABEL_SIZE)
    ax_reg.legend(loc='lower center', bbox_to_anchor=(0.47, 1), shadow=True, ncol=3, fontsize=FONT_SIZE-3)
    ax_reg.set_xlabel(r'$\epsilon$', fontsize= FONT_SIZE)
    ax_reg.set_xticklabels([r'0', r'0.2b', '0.4b', '0.6b', '0.8b', 'b'])

    fig_reg.tight_layout()
    fig_reg.savefig('n_clusters_regular_per.png', dpi=400)

    for ind_param, nb_bin in enumerate(NB_BINS_VARY):
        id = '_'.join([str(MIN_PKT_PROTO), str(nb_bin), 'adaptive'])
        list_acc = [n_clusters[id][x] for x in pers]
        ax_ad.plot(pers, list_acc,  label= r'$b =%d$' % (nb_bin), marker=markers[ind_param], ls=line_styles[ind_param], markersize=8, linewidth=2)

    ax_ad.tick_params(axis='both', which='major', labelsize=LABEL_SIZE)
    ax_ad.legend(loc='lower center', bbox_to_anchor=(0.47, 1), shadow=True, ncol=3, fontsize=FONT_SIZE-3)
    ax_ad.set_xlabel(r'$\epsilon$', fontsize= FONT_SIZE)
    ax_ad.set_xticklabels([r'0', r'0.2b', '0.4b', '0.6b', '0.8b', 'b'])

    fig_ad.tight_layout()
    fig_ad.savefig('n_clusters_adaptive_per.png', dpi=400)

def main(argv):
    init()
    define_adaptive_bins()
    tpr_clusters, fpr_clusters = botFP_clus()
    return 0

if __name__ == '__main__':
    main(sys.argv)
