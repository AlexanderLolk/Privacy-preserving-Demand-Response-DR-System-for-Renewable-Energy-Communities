import boards.board as board

def main():
    public_key = board.get_DSO_public_key()
    user_public_keys = board.get_DSO_user_public_keys()
    user_ids = board.get_ENERGY_agg_id()
    
    print(f"DSO public key: {public_key}")
    print(f"DSO user public keys: {user_public_keys}")
    print(f"Energy agg's user IDs: {user_ids}")

main()