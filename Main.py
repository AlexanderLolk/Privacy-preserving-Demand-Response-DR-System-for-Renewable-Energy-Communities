##### main progress
# Dso make it's key set with schnorr and elgamal. (pk, sk) and (ek, dk)
# smart meters and agg (bluue) makes a schnorr key set (pk, sk)
# agg knows smart meters public key (pk)

# dso checks the id and proof in the pk, and if true, adds them (id, pk) in to a id list

# dso gives own public key to board
# dso signs the list of user and gives it to the board
# dso signs a list of agg and gives it to the board

# dso gives private and public elgamal key to agg (ek, dk)



# .... activions step
#   calls agg's eval on both priv and pub's consumption list with the dk from dso
#  