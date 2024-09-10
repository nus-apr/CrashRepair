import matplotlib
matplotlib.use('Qt5Agg')

import venn

crashrepair = [3,5,9,11,12,13,14,15,18,19,20,26,28,30,32,36,37,39,40,42]
senx = []
extractfix = [3,6,14,28,32]
vulnfix = [3,14,15,18,28,36,38,39,42]
cpr = [11,21,23,25,27,28,32,35,39]


labels2 = venn.get_labels([crashrepair, senx, extractfix, vulnfix, cpr], fill=['number'])
fig2, ax2 = venn.venn5(labels2, names=['CrashRepair', 'SenX', 'ExtractFix', 'VulnFix', 'CPR'])
fig2.savefig("correct.png")
# fig2.show()


crashrepair = [3,4,5,6,7,11,12,13,14,15,18,19,20,21,22,23,25,26,27,28,30,31,32,33,34,35,36,37,38,39,40,42,43]
senx = [13,16,18,22,23,24,25,27,28,31,39]
extractfix = [3,5,6,14,21,22,24,28,29,32,35,37]
vulnfix = [3,4,5,6,7,11,14,15,18,28,32,35,36,38,39,42]
cpr = [1,3,4,5,6,7,8,11,12,13,14,15,17,18,21,22,23,24,25,26,27,28,29,32,33,34,35,36,37,38,39,41,42]

labels = venn.get_labels([crashrepair, senx, extractfix, vulnfix, cpr], fill=['number'])
# fig, ax = venn.venn3(labels, names=['CrashRepair', 'SenX', 'ExtractFix'])

# labels = venn.get_labels([range(10), range(5, 15), range(3, 8)], fill=['number', 'logic'])
fig, ax = venn.venn5(labels, names=['CrashRepair', 'SenX', 'ExtractFix', 'VulnFix', 'CPR'])
fig.legend(ncol=5, loc="lower center")



fig.savefig("plausible.png")
