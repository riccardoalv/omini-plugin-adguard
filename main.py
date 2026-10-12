"""Omini plugin for AdGuard Home (entrypoint run by the Omini core)."""

from omini_sdk import plugin

from omini_adguard.collect import apply, backup, collect, test

plugin.collect(collect)
plugin.test(test)
plugin.apply(apply)
plugin.backup(backup)

if __name__ == "__main__":
    plugin.run()
