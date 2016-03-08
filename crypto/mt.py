import random

# compatible with std::mt19937 in C++
def my_seed(seed):
    state = [seed]
    for _mti in range(0, 623):
        state.append((1812433253 * (state[_mti] ^ (state[_mti] >> 30)) + _mti + 1) & 0xffffffff);
    state.append(624)
    random.setstate((3,tuple(state),None))

def rand():
    return random.getrandbits(32)
