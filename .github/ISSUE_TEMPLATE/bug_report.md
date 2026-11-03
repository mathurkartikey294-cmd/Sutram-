name: Bug Report
description: Report a bug, crash, or unexpected forensic calculation
title: "[BUG]: "
labels: ["bug"]
body:
  - type: textarea
    id: description
    attributes:
      label: Bug Description
      description: Clear and concise description of what went wrong.
    validations:
      required: true
  - type: textarea
    id: reproduction
    attributes:
      label: Steps to Reproduce
      description: Exact steps or curl commands.
    validations:
      required: true
  - type: textarea
    id: expected
    attributes:
      label: Expected Behavior
      description: What should have happened according to forensic standards.
    validations:
      required: true
