import z3

from oracle.laser.smt.solver.solver import Solver as Solver, Optimize as Optimize, BaseSolver as BaseSolver
from oracle.laser.smt.solver.independence_solver import IndependenceSolver as IndependenceSolver
from oracle.laser.smt.solver.solver_statistics import SolverStatistics as SolverStatistics
from oracle.laser._support import args

if args.parallel_solving:
    z3.set_param("parallel.enable", True)
