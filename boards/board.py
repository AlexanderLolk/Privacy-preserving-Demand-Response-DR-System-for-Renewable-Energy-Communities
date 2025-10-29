# this is both for public and private boards
import data.DSO as dso
import aggregators.aggregator as agg
import users.user as user

# DSO, users and aggregators with their public keys
def make_registered_users_and_aggregators():
    return dso.registration()

# Get users from DSO
dso_info, registered_users, registered_aggs = make_registered_users_and_aggregators()

# DR parameters and target reduction
def make_DRparam_and_targetreduction():
    return dso.calculate_DR_param_and_target_reduction()

# noisy list
DSO_ek = dso.create_encryption_key_set() # so that it can be given to all others
reduction_target_list = dso.publish_reduction_target_list()
user.get_DSO_ek(DSO_ek)

###################################################
# MIX Aggregator sends anon mixed pk set to board #
###################################################
def publish_mixed_keys(pk_mixed, πmix):
    print("Published mixed anonymized public keys:", pk_mixed)
    print("Published proof of mixing (πmix):", πmix)

# input for mixing
ID_pk = [(agg_id, agg_val) for agg_id, agg_val in dict(registered_users).items()]

# Use aggregator to mix and anonymize the keys
pk_mixed, r_map, πmix = agg.create_mixed_anon_pk_set(ID_pk)

# Board publishes the mixed keys and proof
publish_mixed_keys(pk_mixed, πmix)

# users get their anon keys from aggregators which is sent to the board
user.get_anon_key()

# get user reports and publish on board
reports = agg.get_report_from_users()

def publish_reports(reports):
    print("=======================")
    print("published user reports:")
    for report in reports:
        print(report)

publish_reports(reports)