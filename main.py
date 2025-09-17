import aggregators.energy as energy

def main():
    supply = energy.get_DSO_supply()
    print(f"DSO supply: {supply}")

main()