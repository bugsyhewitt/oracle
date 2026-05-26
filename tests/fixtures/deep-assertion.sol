// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Depth-sensitivity fixture for oracle's `--max-depth` flag (criterion 7).
//
// The reachable invalid() is gated behind a chain of sequential conditional
// branches. Each `if` adds branch depth to the symbolic path, so the INVALID
// is only reachable once the explorer is allowed enough JUMPI depth. At a
// shallow --max-depth the path to the bug is pruned and NOT reported; at the
// default depth it IS reported.
//
// Trigger: call deep(a,b,c) with all three equal to their gate values. The
// invalid() sits roughly eight branches deep once the ABI dispatcher prologue
// is included — reachable at the default --max-depth 12, pruned at --max-depth 4.
contract DeepAssertion {
    function deep(uint256 a, uint256 b, uint256 c) external pure {
        if (a == 1) {
            if (b == 2) {
                if (c == 3) {
                    assembly {
                        invalid()
                    }
                }
            }
        }
    }
}
