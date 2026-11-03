name: Forensic Detector Task
description: Track the implementation or refinement of a specific forensic detection module
title: "[DETECTOR]: <Media Type> - <Detector Name>"
labels: ["detector", "triage"]
body:
  - type: dropdown
    id: media_type
    attributes:
      label: Media Modality
      options:
        - Image
        - Audio
        - Video
        - Multimodal / Fusion
    validations:
      required: true
  - type: dropdown
    id: category
    attributes:
      label: Forensic Category
      options:
        - synthetic_detection
        - tampering
        - provenance
        - quality
    validations:
      required: true
  - type: input
    id: owner
    attributes:
      label: Assignee / Owner
      placeholder: "e.g., Shivendra (Image), Saksham (Audio), Saarika (Video), Kartikey (Core)"
    validations:
      required: true
  - type: textarea
    id: methodology
    attributes:
      label: Forensic Methodology & Algorithm
      description: Explain the forensic basis (e.g., ELA difference, SyncNet lip-sync lag, wav2vec 2.0 linear probe).
    validations:
      required: true
  - type: textarea
    id: artifacts
    attributes:
      label: Output Evidence & Artifacts
      description: What visual masks, heatmaps, plots, or metric arrays will this detector output for the examiner workbench?
  - type: textarea
    id: limitations
    attributes:
      label: Known Limitations & Quality Boundaries
      description: At what compression level, resolution, or duration does this detector lose calibration?
