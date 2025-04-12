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

