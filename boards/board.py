# this is both for public and private boards
import data.DSO as dso
import utils.ec_elgamal as ahe
import utils.generators as gen

# noisy list
# generate the board's key pair
board_pk, board_sk = ahe.key_gen(gen.pub_param())
encrypted_list = dso.publish_noisy_target_list(board_pk)

print(encrypted_list)

def make_registered_users_and_aggregators():
    return dso.registration()

def make_DRparam_and_targetreduction():
    return dso.calculate_DR_param_and_target_reduction()

def get_registered_users():
    return registered_users

dso_info, registered_users, registered_aggs = make_registered_users_and_aggregators()


# print(registered_users)