# this is both for public and private boards
import data.DSO as dso

registered_users = []
registered_aggs = []

def get_registered_users_and_aggregators():
    registered_users, registered_aggs = dso.registration()

# print(get_registered_users_and_aggregators())