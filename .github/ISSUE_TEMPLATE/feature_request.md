name: Feature Request
description: Propose a new feature, analysis module, or UI enhancement
title: "[FEATURE]: "
labels: ["enhancement"]
body:
  - type: textarea
    id: problem
    attributes:
      label: Forensic Need / Problem Statement
      description: What investigative problem does this feature solve?
    validations:
      required: true
  - type: textarea
    id: proposed_solution
    attributes:
      label: Proposed Solution & Examiner Workflow
      description: How should this work in the workbench, API, or report?
    validations:
      required: true
  - type: dropdown
    id: role_area
    attributes:
      label: Target Area
      options:
        - Backend & Storage (Kartikey)
        - Image Forensics (Shivendra)
        - Audio Forensics (Saksham)
        - Video Forensics (Saarika)
        - Frontend Examiner Workbench
        - Reporting & BSA 63 Certification
