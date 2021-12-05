"""
Generate data for the project
"""

from __future__ import annotations

import argparse
import random
import time
from contextlib import ContextDecorator
from typing import Sequence

from spartancoin import BlockSHA256, BlockSHA512, Transaction
from spartancoin.blocks import Block as _Block

encoded = (
    b"\x01\x00\x00\x00\x021234567890qwertyuiopasdfghjkl;zx\x03\x00\x00"
    b"\x00\xa00F\x02!\x00\xaeY\x94\xd1\xd0\xc12g\xb1\xa9\xfb\x06\xe8"
    b"E(\x15Aw\xedb\xde\x0bd\x06\xf7\x05\xbf7%aY,\x02!\x00\xb6."
    b"\xe4d\"\xc1e1\x00\x17\x93\x98\xb5zt\xfa$3\xdc\xbd\x19l'G\xbf\xb5"
    b"\xc7\xa26\t;\xd50V0\x10\x06\x07*\x86H\xce=\x02\x01\x06"
    b"\x05+\x81\x04\x00\n\x03B\x00\x04N\x9a\xae\xd2G22\x82\xa6+"
    b"\x18_W\xdfW9\xc4U\xc4 \x97e-9=\xa1\xb7\x0bQ\x97\x11sR\xadiR9\xa2"
    b"\nu\xe4\xb6<\xc8\xb3\xe8\x01\x9d\x8e\x01\xc3\x0e\xb4\xa1"
    b"t\xa2\xc8px\\4]\xb0{0987654321qwertyuiopasdfghjkl;zx\x03\x00"
    b"\x00\x00\x9e0D\x02 eY\xb8P\x01\xf7\t\xb0w\xe4\xda}s\xaa1%\n"
    b"(\x11\x95Xy\x1e\x99\x87\x0c\x10\x1d(#%\xf7\x02  \xb4a"
    b"R\xc2\x98\x16\xf3\xf0\x16\x0f}\xb4\x91N\xc8\x87\x19\\\x06\xc6rk"
    b"\xf0\th\x10\xbe\xe1x\xeb\xf80V0\x10\x06\x07*\x86H\xce="
    b"\x02\x01\x06\x05+\x81\x04\x00\n\x03B\x00\x04N\x9a\xae\xd2G22"
    b"\x82\xa6+\x18_W\xdfW9\xc4U\xc4 \x97e-9=\xa1\xb7\x0bQ\x97\x11"
    b"sR\xadiR9\xa2\nu\xe4\xb6<\xc8\xb3\xe8\x01\x9d\x8e\x01\xc3"
    b"\x0e\xb4\xa1t\xa2\xc8px\\4]\xb0{\x01\t\x00\x00\x00\x00\x00"
    b"\x00\x00X0V0\x10\x06\x07*\x86H\xce=\x02\x01\x06\x05+\x81"
    b"\x04\x00\n\x03B\x00\x04N\x9a\xae\xd2G22\x82\xa6+\x18_W\xdfW9\xc4"
    b"U\xc4 \x97e-9=\xa1\xb7\x0bQ\x97\x11sR\xadiR9\xa2\nu\xe4"
    b"\xb6<\xc8\xb3\xe8\x01\x9d\x8e\x01\xc3\x0e\xb4\xa1t\xa2\xc8px\\4"
    b"]\xb0{"
)
t = Transaction.decode(encoded)


class time_it(ContextDecorator):
    """A context manager to time how long something takes"""

    # pylint: disable=attribute-defined-outside-init

    def __enter__(self) -> time_it:
        self.__start = time.perf_counter()
        return self

    def __exit__(self, *_tb_args) -> None:
        self.interval = time.perf_counter() - self.__start


def rand_block_hash() -> bytes:
    """Return a dummy `Transaction`"""
    return b"".join(bytes([b]) for b in random.choices(b"qwertyuiop", k=64))


def main(Block: type[_Block], n: int, difficulty: int) -> list[tuple[float, int]]:
    """Test can hash a block"""
    times_and_tries = []
    for i in range(n):
        block = Block(rand_block_hash(), [t], difficulty=difficulty)
        # print(f"starting {i}... ", end="", flush=True)
        with time_it() as timer:
            block.hash()
        # print(f"took {timer.interval:.3g} seconds and {block.nonce+1} tries")
        times_and_tries.append((timer.interval, block.nonce + 1))
    return times_and_tries


def mean(s: Sequence[float]) -> float:
    """Return the mean of a sequence of numbers"""
    return sum(s) / len(s)


if __name__ == "__main__":
    algos = {"256": BlockSHA256, "512": BlockSHA512}

    parser = argparse.ArgumentParser(
        description="""
            Measure the amount of time it takes to create Spartancoin blocks.
        """
    )
    parser.add_argument("-n", type=int, default=1)
    parser.add_argument("-d", "--difficulty", type=int, default=1)
    parser.add_argument("-a", "--algorithm", type=str, choices=algos, default="256")
    args = parser.parse_args()

    data = main(algos[args.algorithm], args.n, args.difficulty)

    import pandas as pd

    df = pd.DataFrame(data, columns=["time", "tries"])
    print(
        f"median {df.time.median():.3g} seconds "
        f"and {df.tries.median().astype(int)} tries"
    )

    fn = f"a{args.algorithm}n{args.n}d{args.difficulty}.pkl"
    df.to_pickle(fn)
    print(f"saved {fn}")
