# The algorithm Anonym({(pk_i, t, ct_i, σ_i)}i ∈ M , {r′i}_i ∈ M , skT ) allows to the blue aggregator to
# computes (ct_i, t, π_i) corresponding to the pseudo-identity pk′
# i. publish on the private bulletin
# board PBB. For each base line report (pki, (t, cti, σi)), the blue aggregator selects only (cti, t)
# and provides a proof that ensures that the aggregator knows a valid signature on (cti, t) signed
# by pki. It then publishes all (cti, t, πi) on PBB. Additionally, for the verifiability, the blue
# aggregator computes a hash of all published values on PBB, signs it, and publishes it on BB.
# The private bulletin board PBB is an append-only board where both aggregators can write
# on it

def Anonym():
    return ""