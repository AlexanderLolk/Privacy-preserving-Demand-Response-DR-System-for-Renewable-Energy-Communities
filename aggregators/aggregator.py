# the DSO publishes a signed list of registered aggregators on
# BB. The DSO can update the list of registered smart meters and aggregators dynamically

import utils.generators as gen
import os 

NUM_AGG = 4

agg_keys = []
agg_info = {}
agg_names = []
agg_iden = []

def make_aggregator(pp):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    names_path = os.path.join(base_dir, "../aggregators/names.txt")

    # user names and ids
    with open(names_path, "r") as file:
        for line in file:
            words = line.strip().split()
            ids = [word[0] for word in words if word]
            ids = ids[0] + ". " + ids[1] 
            agg_names.append(line.strip())
            agg_iden.append(ids)

    # aggregator's public keys
    for i in range(NUM_AGG):
        agg_id = agg_iden[i]
        ((id, (pk, pp, proof)), sk) = gen.skey_gen(pp)
        verification = (pk, pp, proof)
        agg_info[agg_id] = verification
    return agg_info

def get_agg_signature(pp):
    return make_aggregator(pp)