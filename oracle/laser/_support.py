"""
Minimal support primitives for the forked mythril SMT module.

[Worker decision: mythril's laser/smt/ was copied verbatim into oracle's
tree (see NOTICE). Its only two external dependencies were
`mythril.support.support_utils.Singleton` and `mythril.support.support_args.args`.
Rather than fork the entire `mythril.support` package (which drags in
config/argparse machinery oracle does not use), the two primitives the SMT
module actually consumes are reproduced here, self-contained. `Singleton` is
the standard metaclass; `args` exposes only `parallel_solving`, the single
attribute the solver package reads.]
"""

from typing import Dict


class Singleton(type):
    """A metaclass implementing the singleton pattern.

    Forked from mythril.support.support_utils (Consensys Diligence, MIT).
    """

    _instances: Dict = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class _Args(metaclass=Singleton):
    """Solver tuning flags consumed by the forked SMT module.

    Only the fields the forked smt/solver package reads are reproduced.
    """

    def __init__(self):
        self.parallel_solving = False
        self.solver_timeout = 10000


args = _Args()
