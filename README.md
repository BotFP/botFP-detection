# botFP-detection

This algorithm aims at detecting botnets in a network-centric way, classifying hosts within a network either as bots or benign hosts.
It uses the CTU-13 dataset that must be stored on the local machine, see https://www.stratosphereips.org/datasets-ctu13 for more info.
Our programs aims at analyzing communication patters of hosts with the outside, to recognize the communications specific to a bot.
It uses frequency distributions properties of some communication attributes of the hosts, to fingerprint the bots. Once it learned from known bots, it is able to recognize new occurrences of other kinds of bots.
Two different methods to learn from and to classify the hosts fingerprints are compared: the first one "BotFP-Clus" uses the DBSCAN algorithm to build clusters of hosts, when the second one "BotFP-ML" uses various supervised ML algorithms to do so.

## Put settings

First, you should adjust the settings to your convenience in the *Settings.py* file.
You can choose several parameters including the type and number of bins in the frequency distributions, the value of epsilon in the DBSCAN algorithm, the parameter *m* which is the minimum number of packets to consider an host.

## Launch full detection process

Before launching any Python file, install requirements found in the *requirements.txt* file. Hence you can run:
```
pip install requirements.txt
```

Then you'll be able to run the *detection.py* file. This runs both methods "BotFP-Clus" and "BotFP-ML" and plots figures showing the performances of said algorithms, in terms of TPR, FPR, accuracy and number of clusters.

## Plot additional things

Finally, the *additional_plots.py* file enables:
1. To plot the percentage of traffic per host, in order to finely choose the parameter *m*.
2. To draw the communications of an host per attribute and protocol, in order to understand the differences in their communications patterns.
3. To draw the histograms per host in order to understand the differences in their communications patterns, for different attributes.
