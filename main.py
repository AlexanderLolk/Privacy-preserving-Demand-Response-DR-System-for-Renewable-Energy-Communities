import boards.board as board

def main():
    supply = board.get_DSO_supply()
    public_key = board.get_DSO_public_key()
    user_public_keys = board.get_DSO_user_public_keys()
    print(f"DSO public key: {public_key}")
    print(f"DSO supply: {supply}")
    print(f"DSO user public keys: {user_public_keys}")

main()