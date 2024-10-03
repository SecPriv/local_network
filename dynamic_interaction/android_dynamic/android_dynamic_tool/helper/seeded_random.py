import random

SEED = f"{random.randrange(0, 2**(4*10)):010X}"


seeded_random = random.Random()
seeded_random.seed(SEED)


def reset_seeded_random():
    seeded_random.seed(SEED)
    return SEED
