# this is both for public and private boards
import data.DSO as dso

def make_registered_users_and_aggregators():
    return dso.registration()

def get_registered_users():
    return registered_users

dso_info, registered_users, registered_aggs = make_registered_users_and_aggregators()
print(registered_users)