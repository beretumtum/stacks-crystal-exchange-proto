;; Crystal Exchange Protocol - Secure Asset Transaction Framework

;; Base constants
(define-constant PROTOCOL_SUPERVISOR tx-sender)
(define-constant ERR_UNAUTHORIZED (err u100))
(define-constant ERR_NO_CHAMBER (err u101))
(define-constant ERR_ALREADY_PROCESSED (err u102))
(define-constant ERR_TRANSFER_ERROR (err u103))
(define-constant ERR_INVALID_ID (err u104))
(define-constant ERR_INVALID_QUANTITY (err u105))
(define-constant ERR_INVALID_ORIGINATOR (err u106))
(define-constant ERR_CHAMBER_OUTDATED (err u107))
(define-constant CHAMBER_LIFETIME_BLOCKS u1008) ;; ~7 days

;; Chamber storage mechanism
(define-map ChamberRegistry
  { chamber-id: uint }
  {
    originator: principal,
    beneficiary: principal,
    asset-id: uint,
    quantity: uint,
    chamber-status: (string-ascii 10),
    genesis-block: uint,
    terminus-block: uint
  }
)

;; Current chamber tracking counter
(define-data-var latest-chamber-id uint u0)

;; Utility operations
(define-private (valid-beneficiary? (beneficiary principal))
  (and 
    (not (is-eq beneficiary tx-sender))
    (not (is-eq beneficiary (as-contract tx-sender)))
  )
)

(define-private (valid-chamber-id? (chamber-id uint))
  (<= chamber-id (var-get latest-chamber-id))
)

;; Operational functions

;; Finalize chamber transaction to beneficiary
(define-public (finalize-chamber-transaction (chamber-id uint))
  (begin
    (asserts! (valid-chamber-id? chamber-id) ERR_INVALID_ID)
    (let
      (
        (chamber-data (unwrap! (map-get? ChamberRegistry { chamber-id: chamber-id }) ERR_NO_CHAMBER))
        (beneficiary (get beneficiary chamber-data))
        (quantity (get quantity chamber-data))
        (asset (get asset-id chamber-data))
      )
      (asserts! (or (is-eq tx-sender PROTOCOL_SUPERVISOR) (is-eq tx-sender (get originator chamber-data))) ERR_UNAUTHORIZED)
      (asserts! (is-eq (get chamber-status chamber-data) "pending") ERR_ALREADY_PROCESSED)
      (asserts! (<= block-height (get terminus-block chamber-data)) ERR_CHAMBER_OUTDATED)
      (match (as-contract (stx-transfer? quantity tx-sender beneficiary))
        success
          (begin
            (map-set ChamberRegistry
              { chamber-id: chamber-id }
              (merge chamber-data { chamber-status: "finalized" })
            )
            (print {action: "chamber_finalized", chamber-id: chamber-id, beneficiary: beneficiary, asset-id: asset, quantity: quantity})
            (ok true)
          )
        error ERR_TRANSFER_ERROR
      )
    )
  )
)

;; Prolong chamber lifespan
(define-public (prolong-chamber-lifespan (chamber-id uint) (additional-blocks uint))
  (begin
    (asserts! (valid-chamber-id? chamber-id) ERR_INVALID_ID)
    (asserts! (> additional-blocks u0) ERR_INVALID_QUANTITY)
    (asserts! (<= additional-blocks u1440) ERR_INVALID_QUANTITY) ;; Max ~10 days extension
    (let
      (
        (chamber-data (unwrap! (map-get? ChamberRegistry { chamber-id: chamber-id }) ERR_NO_CHAMBER))
        (originator (get originator chamber-data)) 
        (beneficiary (get beneficiary chamber-data))
        (current-terminus (get terminus-block chamber-data))
        (updated-terminus (+ current-terminus additional-blocks))
      )
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender beneficiary) (is-eq tx-sender PROTOCOL_SUPERVISOR)) ERR_UNAUTHORIZED)
      (asserts! (or (is-eq (get chamber-status chamber-data) "pending") (is-eq (get chamber-status chamber-data) "acknowledged")) ERR_ALREADY_PROCESSED)
      (map-set ChamberRegistry
        { chamber-id: chamber-id }
        (merge chamber-data { terminus-block: updated-terminus })
      )
      (print {action: "chamber_prolonged", chamber-id: chamber-id, requestor: tx-sender, new-terminus-block: updated-terminus})
      (ok true)
    )
  )
)

;; Repatriate assets to originator
(define-public (repatriate-chamber-assets (chamber-id uint))
  (begin
    (asserts! (valid-chamber-id? chamber-id) ERR_INVALID_ID)
    (let
      (
        (chamber-data (unwrap! (map-get? ChamberRegistry { chamber-id: chamber-id }) ERR_NO_CHAMBER))
        (originator (get originator chamber-data))
        (quantity (get quantity chamber-data))
      )
      (asserts! (is-eq tx-sender PROTOCOL_SUPERVISOR) ERR_UNAUTHORIZED)
      (asserts! (is-eq (get chamber-status chamber-data) "pending") ERR_ALREADY_PROCESSED)
      (match (as-contract (stx-transfer? quantity tx-sender originator))
        success
          (begin
            (print {action: "assets_repatriated", chamber-id: chamber-id, originator: originator, quantity: quantity})
            (ok true)
          )
        error ERR_TRANSFER_ERROR
      )
    )
  )
)

;; Originator requests chamber termination
(define-public (terminate-chamber (chamber-id uint))
  (begin
    (asserts! (valid-chamber-id? chamber-id) ERR_INVALID_ID)
    (let
      (
        (chamber-data (unwrap! (map-get? ChamberRegistry { chamber-id: chamber-id }) ERR_NO_CHAMBER))
        (originator (get originator chamber-data))
        (quantity (get quantity chamber-data))
      )
      (asserts! (is-eq tx-sender originator) ERR_UNAUTHORIZED)
      (asserts! (is-eq (get chamber-status chamber-data) "pending") ERR_ALREADY_PROCESSED)
      (asserts! (<= block-height (get terminus-block chamber-data)) ERR_CHAMBER_OUTDATED)
      (match (as-contract (stx-transfer? quantity tx-sender originator))
        success
          (begin
            (map-set ChamberRegistry
              { chamber-id: chamber-id }
              (merge chamber-data { chamber-status: "terminated" })
            )
            (print {action: "chamber_terminated", chamber-id: chamber-id, originator: originator, quantity: quantity})
            (ok true)
          )
        error ERR_TRANSFER_ERROR
      )
    )
  )
)

;; Adjudicate contested chamber with proportional distribution
(define-public (adjudicate-conflict (chamber-id uint) (originator-proportion uint))
  (begin
    (asserts! (valid-chamber-id? chamber-id) ERR_INVALID_ID)
    (asserts! (is-eq tx-sender PROTOCOL_SUPERVISOR) ERR_UNAUTHORIZED)
    (asserts! (<= originator-proportion u100) ERR_INVALID_QUANTITY) ;; Proportion must be 0-100
    (let
      (
        (chamber-data (unwrap! (map-get? ChamberRegistry { chamber-id: chamber-id }) ERR_NO_CHAMBER))
        (originator (get originator chamber-data))
        (beneficiary (get beneficiary chamber-data))
        (quantity (get quantity chamber-data))
        (originator-quantity (/ (* quantity originator-proportion) u100))
        (beneficiary-quantity (- quantity originator-quantity))
      )
      (asserts! (is-eq (get chamber-status chamber-data) "contested") (err u112)) ;; Must be contested
      (asserts! (<= block-height (get terminus-block chamber-data)) ERR_CHAMBER_OUTDATED)

      ;; Transfer originator's portion
      (unwrap! (as-contract (stx-transfer? originator-quantity tx-sender originator)) ERR_TRANSFER_ERROR)

      ;; Transfer beneficiary's portion
      (unwrap! (as-contract (stx-transfer? beneficiary-quantity tx-sender beneficiary)) ERR_TRANSFER_ERROR)
      (print {action: "conflict_adjudicated", chamber-id: chamber-id, originator: originator, beneficiary: beneficiary, 
              originator-quantity: originator-quantity, beneficiary-quantity: beneficiary-quantity, originator-proportion: originator-proportion})
      (ok true)
    )
  )
)

;; Reclaim outdated chamber assets
(define-public (reclaim-outdated-chamber (chamber-id uint))
  (begin
    (asserts! (valid-chamber-id? chamber-id) ERR_INVALID_ID)
    (let
      (
        (chamber-data (unwrap! (map-get? ChamberRegistry { chamber-id: chamber-id }) ERR_NO_CHAMBER))
        (originator (get originator chamber-data))
        (quantity (get quantity chamber-data))
        (expiration (get terminus-block chamber-data))
      )
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender PROTOCOL_SUPERVISOR)) ERR_UNAUTHORIZED)
      (asserts! (or (is-eq (get chamber-status chamber-data) "pending") (is-eq (get chamber-status chamber-data) "acknowledged")) ERR_ALREADY_PROCESSED)
      (asserts! (> block-height expiration) (err u108)) ;; Must be expired
      (match (as-contract (stx-transfer? quantity tx-sender originator))
        success
          (begin
            (map-set ChamberRegistry
              { chamber-id: chamber-id }
              (merge chamber-data { chamber-status: "outdated" })
            )
            (print {action: "outdated_chamber_reclaimed", chamber-id: chamber-id, originator: originator, quantity: quantity})
            (ok true)
          )
        error ERR_TRANSFER_ERROR
      )
    )
  )
)

;; Initiate chamber conflict
(define-public (initiate-chamber-conflict (chamber-id uint) (justification (string-ascii 50)))
  (begin
    (asserts! (valid-chamber-id? chamber-id) ERR_INVALID_ID)
    (let
      (
        (chamber-data (unwrap! (map-get? ChamberRegistry { chamber-id: chamber-id }) ERR_NO_CHAMBER))
        (originator (get originator chamber-data))
        (beneficiary (get beneficiary chamber-data))
      )
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender beneficiary)) ERR_UNAUTHORIZED)
      (asserts! (or (is-eq (get chamber-status chamber-data) "pending") (is-eq (get chamber-status chamber-data) "acknowledged")) ERR_ALREADY_PROCESSED)
      (asserts! (<= block-height (get terminus-block chamber-data)) ERR_CHAMBER_OUTDATED)
      (map-set ChamberRegistry
        { chamber-id: chamber-id }
        (merge chamber-data { chamber-status: "contested" })
      )
      (print {action: "chamber_contested", chamber-id: chamber-id, contestant: tx-sender, justification: justification})
      (ok true)
    )
  )
)

;; Verify digital signature for chamber
(define-public (append-digital-signature (chamber-id uint) (digital-signature (buff 65)))
  (begin
    (asserts! (valid-chamber-id? chamber-id) ERR_INVALID_ID)
    (let
      (
        (chamber-data (unwrap! (map-get? ChamberRegistry { chamber-id: chamber-id }) ERR_NO_CHAMBER))
        (originator (get originator chamber-data))
        (beneficiary (get beneficiary chamber-data))
      )
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender beneficiary)) ERR_UNAUTHORIZED)
      (asserts! (or (is-eq (get chamber-status chamber-data) "pending") (is-eq (get chamber-status chamber-data) "acknowledged")) ERR_ALREADY_PROCESSED)
      (print {action: "signature_appended", chamber-id: chamber-id, signer: tx-sender, signature: digital-signature})
      (ok true)
    )
  )
)

;; Attach chamber reference data
(define-public (attach-reference-data (chamber-id uint) (data-category (string-ascii 20)) (data-fingerprint (buff 32)))
  (begin
    (asserts! (valid-chamber-id? chamber-id) ERR_INVALID_ID)
    (let
      (
        (chamber-data (unwrap! (map-get? ChamberRegistry { chamber-id: chamber-id }) ERR_NO_CHAMBER))
        (originator (get originator chamber-data))
        (beneficiary (get beneficiary chamber-data))
      )
      ;; Only authorized parties can add reference data
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender beneficiary) (is-eq tx-sender PROTOCOL_SUPERVISOR)) ERR_UNAUTHORIZED)
      (asserts! (not (is-eq (get chamber-status chamber-data) "finalized")) (err u160))
      (asserts! (not (is-eq (get chamber-status chamber-data) "repatriated")) (err u161))
      (asserts! (not (is-eq (get chamber-status chamber-data) "outdated")) (err u162))

      ;; Valid data categories
      (asserts! (or (is-eq data-category "asset-details") 
                   (is-eq data-category "transfer-evidence")
                   (is-eq data-category "quality-verification")
                   (is-eq data-category "originator-specs")) (err u163))

      (print {action: "reference_data_attached", chamber-id: chamber-id, data-category: data-category, 
              data-fingerprint: data-fingerprint, submitter: tx-sender})
      (ok true)
    )
  )
)

;; Suspend questionable chamber
(define-public (suspend-questionable-chamber (chamber-id uint) (justification (string-ascii 100)))
  (begin
    (asserts! (valid-chamber-id? chamber-id) ERR_INVALID_ID)
    (let
      (
        (chamber-data (unwrap! (map-get? ChamberRegistry { chamber-id: chamber-id }) ERR_NO_CHAMBER))
        (originator (get originator chamber-data))
        (beneficiary (get beneficiary chamber-data))
      )
      (asserts! (or (is-eq tx-sender PROTOCOL_SUPERVISOR) (is-eq tx-sender originator) (is-eq tx-sender beneficiary)) ERR_UNAUTHORIZED)
      (asserts! (or (is-eq (get chamber-status chamber-data) "pending") 
                   (is-eq (get chamber-status chamber-data) "acknowledged")) 
                ERR_ALREADY_PROCESSED)
      (map-set ChamberRegistry
        { chamber-id: chamber-id }
        (merge chamber-data { chamber-status: "suspended" })
      )
      (print {action: "chamber_suspended", chamber-id: chamber-id, reporter: tx-sender, justification: justification})
      (ok true)
    )
  )
)

;; Create phased transaction chamber
(define-public (create-phased-chamber (beneficiary principal) (asset-id uint) (quantity uint) (phases uint))
  (let 
    (
      (new-id (+ (var-get latest-chamber-id) u1))
      (end-date (+ block-height CHAMBER_LIFETIME_BLOCKS))
      (phase-quantity (/ quantity phases))
    )
    (asserts! (> quantity u0) ERR_INVALID_QUANTITY)
    (asserts! (> phases u0) ERR_INVALID_QUANTITY)
    (asserts! (<= phases u5) ERR_INVALID_QUANTITY) ;; Max 5 phases
    (asserts! (valid-beneficiary? beneficiary) ERR_INVALID_ORIGINATOR)
    (asserts! (is-eq (* phase-quantity phases) quantity) (err u121)) ;; Ensure even division
    (match (stx-transfer? quantity tx-sender (as-contract tx-sender))
      success
        (begin
          (var-set latest-chamber-id new-id)
          (print {action: "phased_chamber_created", chamber-id: new-id, originator: tx-sender, beneficiary: beneficiary, 
                  asset-id: asset-id, quantity: quantity, phases: phases, phase-quantity: phase-quantity})
          (ok new-id)
        )
      error ERR_TRANSFER_ERROR
    )
  )
)
