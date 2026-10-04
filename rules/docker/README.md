Docker-specific hypotheses (`container_stopped`, `container_not_created`,
`port_not_published`, `wrong_published_port`, `port_held_by_container`) are
attached to the network rules in `../network/network.toml`; the `docker`
investigation target is what brings Compose and container evidence in.
