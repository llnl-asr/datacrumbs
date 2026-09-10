##############################################################
# Copyright 2025 Lawrence Livermore National Security, LLC
# (c.f. AUTHORS, NOTICE.LLNS, COPYING)
#
# This file is part of the Flux resource manager framework.
# For details, see https://github.com/flux-framework.
#
# SPDX-License-Identifier: LGPL-3.0
##############################################################

from flux.cli.plugin import CLIPlugin


class DatacrumbsPlugin(CLIPlugin):
    """
    Set the Datacrumbs option.
    """

    def __init__(self, prog, prefix="datacrumbs"):
        super().__init__(prog, prefix=prefix)
        self.add_option(
            "--enable",
            action="store_true",
            default=False,
            help="Enable datacrumbs"
        )
        self.add_option(
            "--probe-file",
            type=str,
            default="",
            help="Path to signed probes json.gz file for datacrumbs"
        )

    def validate(self, jobspec):
        try:
            enable = jobspec.attributes["datacrumbs"]["enable"].lower() == "yes"
            if enable:
                probe_file = jobspec.attributes["datacrumbs"].get("probe_file", "")
                if probe_file == "":
                    raise ValueError("--probe-file is required when datacrumbs is enabled")
        except KeyError:
            enable = False

    def modify_jobspec(self, args, jobspec):
        if args.enable:
            jobspec.setattr("datacrumbs.enable", "yes")
            jobspec.setattr("datacrumbs.probe_file", args.probe_file)
        else:
            jobspec.setattr("datacrumbs.enable", "no")
            jobspec.setattr("datacrumbs.probe_file", "")
