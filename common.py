def hexify(stringthing):
    return "".join(format(x, '02x') for x in stringthing)
