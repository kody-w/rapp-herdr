# rapp-herdr

Run RAPP neighborhoods as supervised Herdr workspaces.

The integration projects one neighborhood into one Herdr workspace and gives
each local Twin its own tab, terminal process, identity, lifecycle state, and
port. It is additive: RAPP manifests remain application data, Twin kernels stay
unchanged, and Herdr is controlled only through its public CLI and lifecycle
APIs.

Implementation is being developed on a feature branch so `main` remains a
stable bootstrap point.
