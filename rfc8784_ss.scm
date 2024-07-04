(herald IKEv2-PSK (algebra diffie-hellman))

;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Model simplifications ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; 1. We ignore TSi and TSr (the traffic selectors)
;; 2. 

;;;;;;;;;;;;
;; Macros ;;
;;;;;;;;;;;;

;; Since initiator and responder have different expressions for the
;; DH public values and derived keys in messages, the macros are
;; parameterized by the DH values and keys

;; Key material for initial exchange
(defmacro (KEYSEED dhkey) (prf (cat n_init n_resp) dhkey))
(defmacro (S) (cat n_init n_resp SPI_init SPI_resp))
(defmacro (generatedKey dhkey) (cat (KEYSEED dhkey) (S)))

(defmacro (SK_d_prime dhkey) (hash (generatedKey dhkey) "d"))
(defmacro (SK_ai dhkey) (hash (generatedKey dhkey) "ai"))
(defmacro (SK_ar dhkey) (hash (generatedKey dhkey) "ar"))
(defmacro (SK_ei dhkey) (hash (generatedKey dhkey) "ei"))
(defmacro (SK_er dhkey) (hash (generatedKey dhkey) "er"))
(defmacro (SK_pi_prime dhkey) (hash (generatedKey dhkey) "pi"))
(defmacro (SK_pr_prime dhkey) (hash (generatedKey dhkey) "pr"))
(defmacro (SK_d dhkey) (prf ppk (cat (SK_d_prime dhkey) "0x01")))
(defmacro (SK_pi dhkey) (prf ppk (cat (SK_pi_prime dhkey) "0x01")))
(defmacro (SK_pr dhkey) (prf ppk (cat (SK_pr_prime dhkey) "0x01")))

(defmacro (initialChild_KEYMAT dhkey) (hash (SK_d dhkey) n_init n_resp))

;; Macros for msg1 and msg2
(defmacro (msg1 ipub)(cat SPI_init "0" "msg1" "SAi1_algorithms" ipub n_init "notify_useppk"))
(defmacro (msg2 rpub)(cat SPI_init SPI_resp "msg2" "SAr1_algorithms" rpub n_resp "notify_useppk"))

;; Macros for msg 3
(defmacro (signed_octets_init ipub dhkey) (cat (msg1 ipub) n_resp (hmac ID_init (SK_pi dhkey))))
(defmacro (auth_init ipub dhkey) (hash (hash psk "KeyPadforIKEv2")  (signed_octets_init ipub dhkey)))

(defmacro (msg3_content ipub dhkey)(cat ID_init (auth_init ipub dhkey) "SAi2_algorithms" SPI_init2 "use_ppk" id_ppk) )
(defmacro (msg3 ipub dhkey)(cat SPI_init SPI_resp "msg3" (enc  (msg3_content ipub dhkey) (SK_ei dhkey)) (hmac (msg3_content ipub dhkey) (SK_ai dhkey))))

;; Macros for msg 4
(defmacro (signed_octets_resp rpub dhkey) (cat "SAr1_algorithms" rpub n_resp "notify_useppk" n_init (hmac ID_resp (SK_pr dhkey))))
(defmacro (auth_resp rpub dhkey) (hash (hash psk "KeyPadforIKEv2")  (signed_octets_resp rpub dhkey)))

(defmacro (msg4_content rpub dhkey)(cat ID_resp (auth_resp rpub dhkey) "SAr2_algorithms" SPI_resp2 "use_ppk"))
(defmacro (msg4 rpub dhkey)(cat SPI_init SPI_resp "msg4" (enc  (msg4_content rpub dhkey) (SK_er dhkey)) (hmac (msg4_content rpub dhkey) (SK_ar dhkey))))

;; Macros for rekey
(defmacro (rekey_init_content ipub_rekey)(cat "SAi_rekey_algorithms" SPIrk_init nrk_init ipub_rekey))
(defmacro (rekey_init ipub_rekey dhkey)(cat SPI_init SPI_resp "rekey_init" (enc  (rekey_init_content ipub_rekey) (SK_ei dhkey)) (hmac (rekey_init_content ipub_rekey) (SK_ai dhkey))))

(defmacro (rekey_resp_content rpub_rekey)(cat "SAr_rekey_algorithms" SPIrk_init SPIrk_resp nrk_resp rpub_rekey))
(defmacro (rekey_resp rpub_rekey dhkey)(cat SPI_init SPI_resp "rekey_resp" (enc  (rekey_resp_content rpub_rekey) (SK_er dhkey)) (hmac (rekey_resp_content rpub_rekey) (SK_ar dhkey))))

;; Rekey key material
; SKEYSEED = prf(SK_d (old), g^ir (new) | Ni | Nr)
; {SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr}
;                   = prf+ (SKEYSEED, Ni | Nr | SPIi | SPIr)
(defmacro (rekey_SKEYSEED dhkey rekey_dhkey) (hash (SK_d dhkey) rekey_dhkey nrk_init nrk_resp))
(defmacro (rekey_S) (cat nrk_init nrk_resp SPIrk_init SPIrk_resp))
(defmacro (rekey_GenKey dhkey rekey_dhkey) (cat (rekey_SKEYSEED dhkey rekey_dhkey) (rekey_S)))

(defmacro (rekey_SK_d dhkey rekey_dhkey) (hash (rekey_GenKey dhkey rekey_dhkey) "d"))
(defmacro (rekey_SK_ai dhkey rekey_dhkey) (hash (rekey_GenKey dhkey rekey_dhkey) "ai"))
(defmacro (rekey_SK_ar dhkey rekey_dhkey) (hash (rekey_GenKey dhkey rekey_dhkey) "ar"))
(defmacro (rekey_SK_ei dhkey rekey_dhkey) (hash (rekey_GenKey dhkey rekey_dhkey) "ei"))
(defmacro (rekey_SK_er dhkey rekey_dhkey) (hash (rekey_GenKey dhkey rekey_dhkey) "er"))

;; Macros for create_child 
(defmacro (create_child_init_content ipub_cc)(cat "SAi_create_child_algorithms" SPIcc_init ncc_init ipub_cc))
(defmacro (create_child_init ipub_cc SKei SKai )(cat SPI_init SPI_resp "create_child" (enc  (create_child_init_content ipub_cc) SKei) (hmac (create_child_init_content ipub_cc) SKai)))

(defmacro (create_child_resp_content rpub_cc)(cat "SAr_create_child_algorithms" SPIcc_init SPIcc_resp ncc_resp rpub_cc))
(defmacro (create_child_resp rpub_cc SKer SKar)(cat SPI_init SPI_resp "create_child" (enc  (create_child_resp_content rpub_cc) SKer) (hmac (create_child_resp_content rpub_cc) SKar)))

;; ChildSA key material
; KEYMAT = prf+(SK_d, g^ir (new) | Ni | Nr)

(defmacro (child_KEYMAT SKd_old child_dhkey) (hash SKd_old child_dhkey ncc_init ncc_resp))
; TO DO: delete the below?
;(defmacro (child_S) (cat ncc_init ncc_resp SPIcc_init SPIcc_resp))
;(defmacro (child_GenKey SKd_old child_dhkey) (cat (child_SKEYSEED SKd_old child_dhkey) (child_S)))

;(defmacro (child_SK_d SKd_old child_dhkey) (hash (child_GenKey SKd_old child_dhkey) "d"))
;(defmacro (child_SK_ai SKd_old child_dhkey) (hash (child_GenKey SKd_old child_dhkey) "ai"))
;(defmacro (child_SK_ar SKd_old child_dhkey) (hash (child_GenKey SKd_old child_dhkey) "ar"))
;(defmacro (child_SK_ei SKd_old child_dhkey) (hash (child_GenKey SKd_old child_dhkey) "ei"))
;(defmacro (child_SK_er  SKd_old child_dhkey) (hash (child_GenKey SKd_old child_dhkey) "er"))



;;;;;;;;;;;;;;
;; Protocol ;;
;;;;;;;;;;;;;;

(defprotocol ikev2_psk diffie-hellman
  (defrole init-rc
    (vars (i rki cci rndx) (SPI_init SPI_resp n_init n_resp SPI_init2 SPI_resp2 nrk_init nrk_resp SPIrk_init SPIrk_resp SPIcc_init SPIcc_resp ncc_init ncc_resp data ) (gr grkr gccr base )
	  (psk ppk skey )(ID_init ID_resp id_ppk name)      
      )
    (trace
     (send (msg1 (exp (gen) i)))
     (recv (msg2 gr))
     (send (msg3 (exp (gen) i) (exp gr i)))
     (recv (msg4 gr (exp gr i)) )
     ;; send rekey request
     (send (rekey_init (exp (gen) rki) (exp gr i)))
     (recv (rekey_resp grkr (exp gr i)))     
     ;; send create child request
     (send (create_child_init (exp (gen) cci) (rekey_SK_ei (exp gr i) (exp grkr rki)) (rekey_SK_ai (exp gr i) (exp grkr rki))))
     (recv (create_child_resp gccr (rekey_SK_er (exp gr i) (exp grkr rki)) (rekey_SK_ar (exp gr i) (exp grkr rki))))
    )

    ;; Adds a fact introducing the existence of ID_resp1 associated to psk
    (assume (exists ((ID_resp1 name)) (fact pskIDs psk ID_init ID_resp1)))
    ;; bind id_ppk and ppk 
    (facts (isKeyIDFor id_ppk ppk))
    ;; i, rki, ci does not act as uniq-gen with quantum adversary
    (uniq-gen SPI_init n_init SPI_init2 nrk_init SPIrk_init SPIcc_init ncc_init) 
    (non-orig psk ppk)
    )
    
  (defrole resp-rc
    (vars (r rkr ccr rndx) (SPI_init SPI_resp n_init n_resp SPI_init2 SPI_resp2 nrk_init nrk_resp SPIrk_init SPIrk_resp SPIcc_init SPIcc_resp ncc_init ncc_resp data ) (gi grki gcci base )
	  (psk ppk skey ) (ID_init ID_resp id_ppk name )      
      )
    (trace
     (recv (msg1 gi))
     (send (msg2 (exp (gen)r)))
     (recv (msg3 gi (exp gi r)))
     (send (msg4 (exp (gen)r) (exp gi r)))
     ;; receive rekey request
     (recv (rekey_init grki (exp gi r)))
     (send (rekey_resp (exp (gen)rkr) (exp gi r)))
     ;; receive create_child request
     (recv (create_child_init gcci (rekey_SK_ei (exp gi r) (exp grki rkr)) (rekey_SK_ai (exp gi r) (exp grki rkr))))
     (send (create_child_resp (exp (gen) ccr) (rekey_SK_er (exp gi r) (exp grki rkr)) (rekey_SK_ar (exp gi r) (exp grki rkr))))
    )
    (facts (pskIDs psk ID_init ID_resp)
           (isKeyIDFor id_ppk ppk))
     ;; r, cr, rkr do not act as uniq-gen with quantum adversary
    (uniq-gen SPI_resp n_resp SPI_resp2 nrk_resp SPIrk_resp SPIcc_resp ncc_resp) 
    (non-orig psk ppk)
    )

  
  
  (defrole init-cr
    (vars (i rki cci rndx) (SPI_init SPI_resp n_init n_resp SPI_init2 SPI_resp2 nrk_init nrk_resp SPIrk_init SPIrk_resp SPIcc_init SPIcc_resp ncc_init ncc_resp data ) (gr grkr gccr base )
	  (psk ppk skey )(ID_init ID_resp id_ppk name)      
      )
    (trace
     (send (msg1 (exp (gen) i)))
     (recv (msg2 gr))
     (send (msg3 (exp (gen) i) (exp gr i)))
     (recv (msg4 gr (exp gr i)) )
     ;; send create child request
     (send (create_child_init (exp (gen) cci) (SK_ei (exp gr i)) (SK_ai (exp gr i)) ))
     (recv (create_child_resp gccr (SK_er (exp gr i)) (SK_ar (exp gr i)) ))
     ;; send rekey request
     (send (rekey_init (exp (gen) rki) (exp gr i)))
     (recv (rekey_resp grkr (exp gr i)))     
    )

    ;; Adds a fact introducing the existence of ID_resp1 associated to psk
    (assume (exists ((ID_resp1 name)) (fact pskIDs psk ID_init ID_resp1)))
    ;; bind id_ppk and ppk 
    (facts (isKeyIDFor id_ppk ppk))
    ;; i, rki, ci does not act as uniq-gen with quantum adversary
    (uniq-gen SPI_init n_init SPI_init2 nrk_init SPIrk_init SPIcc_init ncc_init) 
    (non-orig psk ppk)
  )

  (defrole resp-cr
     (vars (r rkr ccr rndx) (SPI_init SPI_resp n_init n_resp SPI_init2 SPI_resp2 nrk_init nrk_resp SPIrk_init SPIrk_resp SPIcc_init SPIcc_resp ncc_init ncc_resp data ) (gi grki gcci base )
	  (psk ppk skey ) (ID_init ID_resp id_ppk name )      
      )
    (trace
     (recv (msg1 gi))
     (send (msg2 (exp (gen)r)))
     (recv (msg3 gi (exp gi r)))
     (send (msg4 (exp (gen)r) (exp gi r)))
     ;; recv create child request
     (recv (create_child_init gcci (SK_ei (exp gi r)) (SK_ai (exp gi r)) ))
     (send (create_child_resp (exp (gen) ccr) (SK_er (exp gi r)) (SK_ar (exp gi r)) ))

     ;; receive rekey request
     (recv (rekey_init grki (exp gi r)))
     (send (rekey_resp (exp (gen)rkr) (exp gi r)))
    )
    (facts (pskIDs psk ID_init ID_resp)
           (isKeyIDFor id_ppk ppk))
     ;; r, cr, rkr do not act as uniq-gen with quantum adversary
    (uniq-gen SPI_resp n_resp SPI_resp2 nrk_resp SPIrk_resp SPIcc_resp ncc_resp) 
    (non-orig psk ppk)
    )

  ;;;;;;;;;;;
  ;; RULES ;;
  ;;;;;;;;;;;

  ;; A given psk can only be associated with two names
  ;; (in the order of the initiator"s name followed by responder"s name)
  (defrule IDs_eq
    (forall
     ((ID_init1 ID_init2 ID_resp1 ID_resp2 name) (psk skey))
     (implies
      (and (fact pskIDs psk ID_init1 ID_resp1)
	         (fact pskIDs psk ID_init2 ID_resp2))
      (and (= ID_init1 ID_init2)
	         (= ID_resp1 ID_resp2)))))

  ;; If z is an initiator strand with psk, and there is
  ;; a fact saying that the IDs associated with psk are
  ;; ID_init and ID_resp, then add a fact saying that
  ;; the peer ID of strand z is ID_resp.
  (defrule peerID_intro_rc
    (forall
     ((ID_init ID_resp name) (psk skey) (z strd))
     (implies
      (and (p "init-rc" "psk" z psk)
	         (fact pskIDs psk ID_init ID_resp))
      (fact peerID z ID_resp))))

  (defrule peerID_intro_cr
    (forall
     ((ID_init ID_resp name) (psk skey) (z strd))
     (implies
      (and (p "init-cr" "psk" z psk)
	         (fact pskIDs psk ID_init ID_resp))
      (fact peerID z ID_resp))))


  ;; Ensure that peerID and the initiator role predicate for ID_resp
  ;; agree. This allows us to introduce (peerID z ID_resp) before
  ;; (p "init" "ID_resp" z ID_resp) is definable. 
  (defrule peerID_semantics_rc
    (forall
     ((ID_resp1 ID_resp2 name) (z strd))
     (implies
      (and (p "init-rc" "ID_resp" z ID_resp1)
	         (fact peerID z ID_resp2))
      (= ID_resp1 ID_resp2))))

  (defrule peerID_semantics_cr
    (forall
     ((ID_resp1 ID_resp2 name) (z strd))
     (implies
      (and (p "init-cr" "ID_resp" z ID_resp1)
	         (fact peerID z ID_resp2))
      (= ID_resp1 ID_resp2))))

  ;; Two ppks with the same ID are the same
  (defrule id_ppk_inj1
    (forall
     ((id_ppk name) (ppk1 ppk2 skey))
     (implies
      (and (fact isKeyIDFor id_ppk ppk1)
	         (fact isKeyIDFor id_ppk ppk2))
      (= ppk1 ppk2))))

  ;; Two IDs for the same ppk are the same
  (defrule id_ppk_inj2
    (forall
     ((id_ppk1 id_ppk2 name) (ppk skey))
     (implies
      (and (fact isKeyIDFor id_ppk1 ppk)
	   (fact isKeyIDFor id_ppk2 ppk))
      (= id_ppk1 id_ppk2))))

  (lang 
	(hmac hash)
	(prf hash))
)

(comment 

;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Sanity check that      ;;
;; the protocol completes ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; Verify that the protocol can complete a rekey AND create child as expected
(defskeleton ikev2_psk
  (vars
    (SPI_init SPI_resp n_init n_resp SPI_init2 SPI_resp2 nrk_init
      nrk_resp SPIrk_init SPIrk_resp SPIcc_init 
      SPIcc_resp data) (psk ppk skey) (ID_init id_ppk ID_resp name)
    (i rki cci r rkr ccr rndx))
  (defstrand init-rc 8 (SPI_init SPI_init) (SPI_resp SPI_resp)
    (n_init n_init) (n_resp n_resp) (SPI_init2 SPI_init2)
    (SPI_resp2 SPI_resp2) (nrk_init nrk_init) (nrk_resp nrk_resp)
    (SPIrk_init SPIrk_init) (SPIrk_resp SPIrk_resp)
    (SPIcc_init SPIcc_init) (SPIcc_resp SPIcc_resp) (psk psk) (ppk ppk)
    (ID_init ID_init) (ID_resp ID_resp) (id_ppk id_ppk)
    (gr (exp (gen) r)) (grkr (exp (gen) rkr)) (gccr (exp (gen) ccr))
    (i i) (rki rki) (cci cci))
  (defstrand resp-rc 8 (SPI_init SPI_init) (SPI_resp SPI_resp)
    (n_init n_init) (n_resp n_resp) (SPI_init2 SPI_init2)
    (SPI_resp2 SPI_resp2) (nrk_init nrk_init) (nrk_resp nrk_resp)
    (SPIrk_init SPIrk_init) (SPIrk_resp SPIrk_resp)
    (SPIcc_init SPIcc_init) (SPIcc_resp SPIcc_resp) (psk psk) (ppk ppk)
    (ID_init ID_init) (ID_resp ID_resp) (id_ppk id_ppk)
    (gi (exp (gen) i)) (grki (exp (gen) rki)) (gcci (exp (gen) cci))
    (r r) (rkr rkr) (ccr ccr))
  (precedes ((0 0) (1 0)) ((0 2) (1 2)) ((0 4) (1 4)) ((0 6) (1 6))
    ((1 1) (0 1)) ((1 3) (0 3)) ((1 5) (0 5)) ((1 7) (0 7)))
  (comment "Existence: rekey then create child is possible") 
)


;; Verify that the protocol can complete a create child and later rekey as expected
(defskeleton ikev2_psk
  (vars
    (SPI_init SPI_resp n_init n_resp SPI_init2 SPI_resp2 nrk_init
      nrk_resp SPIrk_init SPIrk_resp SPIcc_init 
      SPIcc_resp data) (psk ppk skey) (ID_init id_ppk ID_resp name)
    (i rki cci r rkr ccr rndx))
  (defstrand init-cr 8 (SPI_init SPI_init) (SPI_resp SPI_resp)
    (n_init n_init) (n_resp n_resp) (SPI_init2 SPI_init2)
    (SPI_resp2 SPI_resp2) (nrk_init nrk_init) (nrk_resp nrk_resp)
    (SPIrk_init SPIrk_init) (SPIrk_resp SPIrk_resp)
    (SPIcc_init SPIcc_init) (SPIcc_resp SPIcc_resp) (psk psk) (ppk ppk)
    (ID_init ID_init) (ID_resp ID_resp) (id_ppk id_ppk)
    (gr (exp (gen) r)) (grkr (exp (gen) rkr)) (gccr (exp (gen) ccr))
    (i i) (rki rki) (cci cci))
  (defstrand resp-cr 8 (SPI_init SPI_init) (SPI_resp SPI_resp)
    (n_init n_init) (n_resp n_resp) (SPI_init2 SPI_init2)
    (SPI_resp2 SPI_resp2) (nrk_init nrk_init) (nrk_resp nrk_resp)
    (SPIrk_init SPIrk_init) (SPIrk_resp SPIrk_resp)
    (SPIcc_init SPIcc_init) (SPIcc_resp SPIcc_resp) (psk psk) (ppk ppk)
    (ID_init ID_init) (ID_resp ID_resp) (id_ppk id_ppk)
    (gi (exp (gen) i)) (grki (exp (gen) rki)) (gcci (exp (gen) cci))
    (r r) (rkr rkr) (ccr ccr))
  (precedes ((0 0) (1 0)) ((0 2) (1 2)) ((0 4) (1 4)) ((0 6) (1 6))
    ((1 1) (0 1)) ((1 3) (0 3)) ((1 5) (0 5)) ((1 7) (0 7)))
  (comment "Existence: create child then rekey is possible") 
)

END COMMENT)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Preliminary exploration  ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defskeleton ikev2_psk
  (vars
    (SPI_init SPI_resp n_init n_resp SPI_init2 SPI_resp2 data) (psk ppk skey) (ID_init id_ppk ID_resp name)
    (i r rndx))
  (defstrand init-rc 4 (SPI_init SPI_init) (SPI_resp SPI_resp)
    (n_init n_init) (n_resp n_resp) (SPI_init2 SPI_init2)
    (SPI_resp2 SPI_resp2) (psk psk) (ppk ppk)
    (ID_init ID_init) (ID_resp ID_resp) (id_ppk id_ppk)
    (gr (exp (gen) r)) (i i))
   (comment "analyse IKE_SA from the initiator's perspective") 
)

;; TO DO: what happens when I move the uniq-gen of SPIs and nonces to here (restricting them to relevant party)
(defskeleton ikev2_psk
  (vars
    (SPI_init SPI_resp n_init n_resp SPI_init2 SPI_resp2 nrk_init
      nrk_resp SPIrk_init SPIrk_resp SPIcc_init 
      SPIcc_resp data) (psk ppk skey) (ID_init id_ppk ID_resp name)
    (i rki cci r rkr ccr rndx))
  (defstrand init-rc 8 (SPI_init SPI_init) (SPI_resp SPI_resp)
    (n_init n_init) (n_resp n_resp) (SPI_init2 SPI_init2)
    (SPI_resp2 SPI_resp2) (nrk_init nrk_init) (nrk_resp nrk_resp)
    (SPIrk_init SPIrk_init) (SPIrk_resp SPIrk_resp)
    (SPIcc_init SPIcc_init) (SPIcc_resp SPIcc_resp) (psk psk) (ppk ppk)
    (ID_init ID_init) (ID_resp ID_resp) (id_ppk id_ppk)
    (gr (exp (gen) r)) (grkr (exp (gen) rkr)) (gccr (exp (gen) ccr))
    (i i) (rki rki) (cci cci))
   (comment "analyse rekey then create child from the initiator's perspective") 
)

(defskeleton ikev2_psk
  (vars
    (SPI_init SPI_resp n_init n_resp SPI_init2 SPI_resp2 nrk_init
      nrk_resp SPIrk_init SPIrk_resp SPIcc_init 
      SPIcc_resp data) (psk ppk skey) (ID_init id_ppk ID_resp name)
    (i rki cci r rkr ccr rndx))
  (defstrand resp-rc 8 (SPI_init SPI_init) (SPI_resp SPI_resp)
    (n_init n_init) (n_resp n_resp) (SPI_init2 SPI_init2)
    (SPI_resp2 SPI_resp2) (nrk_init nrk_init) (nrk_resp nrk_resp)
    (SPIrk_init SPIrk_init) (SPIrk_resp SPIrk_resp)
    (SPIcc_init SPIcc_init) (SPIcc_resp SPIcc_resp) (psk psk) (ppk ppk)
    (ID_init ID_init) (ID_resp ID_resp) (id_ppk id_ppk)
    (gi (exp (gen) i)) (grki (exp (gen) rki)) (gcci (exp (gen) cci))
    (r r) (rkr rkr) (ccr ccr))
   (comment "analyse rekey then create child from the responder's perspective") 
)

(defskeleton ikev2_psk
  (vars
    (SPI_init SPI_resp n_init n_resp SPI_init2 SPI_resp2 nrk_init
      nrk_resp SPIrk_init SPIrk_resp SPIcc_init 
      SPIcc_resp data) (psk ppk skey) (ID_init id_ppk ID_resp name)
    (i rki cci r rkr ccr rndx))
  (defstrand init-cr 8 (SPI_init SPI_init) (SPI_resp SPI_resp)
    (n_init n_init) (n_resp n_resp) (SPI_init2 SPI_init2)
    (SPI_resp2 SPI_resp2) (nrk_init nrk_init) (nrk_resp nrk_resp)
    (SPIrk_init SPIrk_init) (SPIrk_resp SPIrk_resp)
    (SPIcc_init SPIcc_init) (SPIcc_resp SPIcc_resp) (psk psk) (ppk ppk)
    (ID_init ID_init) (ID_resp ID_resp) (id_ppk id_ppk)
    (gr (exp (gen) r)) (grkr (exp (gen) rkr)) (gccr (exp (gen) ccr))
    (i i) (rki rki) (cci cci))
   (comment "analyse create child then rekey from the initiator's perspective") 
)

(defskeleton ikev2_psk
  (vars
    (SPI_init SPI_resp n_init n_resp SPI_init2 SPI_resp2 nrk_init
      nrk_resp SPIrk_init SPIrk_resp SPIcc_init 
      SPIcc_resp data) (psk ppk skey) (ID_init id_ppk ID_resp name)
    (i rki cci r rkr ccr rndx))
  (defstrand resp-cr 8 (SPI_init SPI_init) (SPI_resp SPI_resp)
    (n_init n_init) (n_resp n_resp) (SPI_init2 SPI_init2)
    (SPI_resp2 SPI_resp2) (nrk_init nrk_init) (nrk_resp nrk_resp)
    (SPIrk_init SPIrk_init) (SPIrk_resp SPIrk_resp)
    (SPIcc_init SPIcc_init) (SPIcc_resp SPIcc_resp) (psk psk) (ppk ppk)
    (ID_init ID_init) (ID_resp ID_resp) (id_ppk id_ppk)
    (gi (exp (gen) i)) (grki (exp (gen) rki)) (gcci (exp (gen) cci))
    (r r) (rkr rkr) (ccr ccr))
   (comment "analyse create child then rekey from the responder's perspective") 
)



(comment SECRECY
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Secrecy properties for IKE_SA ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; This section checks the secrecy of the seven keys generated in IKE_SA, as well as the keys generated in the automatically created Child_SA 
; QUESTION: To be entirely thorough, this must be checked over all init-rc and init-cr defroles
; The absence of a shape confirms secrecy

(defgoal ikev2_psk
  (forall 
    ((SPI_init n_init SPI_resp n_resp data)(ppk skey)(gr base)(i rndx)(z z-0 strd))
  (implies 
    (and 
      (p "init-rc" z 4)
      (p "init-rc" "SPI_init" z SPI_init)
      (p "init-rc" "SPI_resp" z SPI_resp)
      (p "init-rc" "n_init" z n_init)
      (p "init-rc" "n_resp" z n_resp)  
      (p "init-rc" "ppk" z ppk)
      (p "init-rc" "gr" z gr)
      (p "init-rc" "i" z i)
      (p "" z-0 1)
      (p "" "x" z-0 (SK_ai (exp gr i)))
    )
    (false))
  )
  (comment Probe confidentiality of SK_ai))

(defgoal ikev2_psk
  (forall 
    ((SPI_init n_init SPI_resp n_resp data)(ppk skey)(gr base)(i rndx)(z z-0 strd))
  (implies 
    (and 
      (p "init-rc" z 4)
      (p "init-rc" "SPI_init" z SPI_init)
      (p "init-rc" "SPI_resp" z SPI_resp)
      (p "init-rc" "n_init" z n_init)
      (p "init-rc" "n_resp" z n_resp)  
      (p "init-rc" "ppk" z ppk)
      (p "init-rc" "gr" z gr)
      (p "init-rc" "i" z i)
      (p "" z-0 1)
      (p "" "x" z-0 (SK_ar (exp gr i)))
    )
    (false))
  )
  (comment Probe confidentiality of SK_ar))

(defgoal ikev2_psk
  (forall 
    ((SPI_init n_init SPI_resp n_resp data)(ppk skey)(gr base)(i rndx)(z z-0 strd))
  (implies 
    (and 
      (p "init-rc" z 4)
      (p "init-rc" "SPI_init" z SPI_init)
      (p "init-rc" "SPI_resp" z SPI_resp)
      (p "init-rc" "n_init" z n_init)
      (p "init-rc" "n_resp" z n_resp)  
      (p "init-rc" "ppk" z ppk)
      (p "init-rc" "gr" z gr)
      (p "init-rc" "i" z i)
      (p "" z-0 1)
      (p "" "x" z-0 (SK_ei (exp gr i)))
    )
    (false))
  )
  (comment Probe confidentiality of SK_ei))

(defgoal ikev2_psk
  (forall 
    ((SPI_init n_init SPI_resp n_resp data)(ppk skey)(gr base)(i rndx)(z z-0 strd))
  (implies 
    (and 
      (p "init-rc" z 4)
      (p "init-rc" "SPI_init" z SPI_init)
      (p "init-rc" "SPI_resp" z SPI_resp)
      (p "init-rc" "n_init" z n_init)
      (p "init-rc" "n_resp" z n_resp)  
      (p "init-rc" "ppk" z ppk)
      (p "init-rc" "gr" z gr)
      (p "init-rc" "i" z i)
      (p "" z-0 1)
      (p "" "x" z-0 (SK_er (exp gr i)))
    )
    (false))
  )
  (comment Probe confidentiality of SK_er))

(defgoal ikev2_psk
  (forall 
  ((SPI_init n_init SPI_resp n_resp data)(ppk skey)(gr base)(i rndx)(z z-0 strd))
  (implies 
    (and 
      (p "init-rc" z 4)
      (p "init-rc" "SPI_init" z SPI_init)
      (p "init-rc" "SPI_resp" z SPI_resp)
      (p "init-rc" "n_init" z n_init)
      (p "init-rc" "n_resp" z n_resp)  
      (p "init-rc" "ppk" z ppk)
      (p "init-rc" "gr" z gr)
      (p "init-rc" "i" z i)
      (p "" z-0 1)
      (p "" "x" z-0 (SK_d (exp gr i)))
    )
    (false))
  )
  (comment Probe confidentiality of SK_d))

(defgoal ikev2_psk
  (forall 
  ((SPI_init n_init SPI_resp n_resp data)(ppk skey)(gr base)(i rndx)(z z-0 strd))
  (implies 
    (and 
      (p "init-rc" z 4)
      (p "init-rc" "SPI_init" z SPI_init)
      (p "init-rc" "SPI_resp" z SPI_resp)
      (p "init-rc" "n_init" z n_init)
      (p "init-rc" "n_resp" z n_resp)  
      (p "init-rc" "ppk" z ppk)
      (p "init-rc" "gr" z gr)
      (p "init-rc" "i" z i)
      (p "" z-0 1)
      (p "" "x" z-0 (SK_pi (exp gr i)))
    )
    (false))
  )
  (comment Probe confidentiality of SK_pi))

(defgoal ikev2_psk
  (forall 
  ((SPI_init n_init SPI_resp n_resp data)(ppk skey)(gr base)(i rndx)(z z-0 strd))
  (implies 
    (and 
      (p "init-rc" z 4)
      (p "init-rc" "SPI_init" z SPI_init)
      (p "init-rc" "SPI_resp" z SPI_resp)
      (p "init-rc" "n_init" z n_init)
      (p "init-rc" "n_resp" z n_resp)  
      (p "init-rc" "ppk" z ppk)
      (p "init-rc" "gr" z gr)
      (p "init-rc" "i" z i)
      (p "" z-0 1)
      (p "" "x" z-0 (SK_pr (exp gr i)))
    )
    (false))
  )
  (comment Probe confidentiality of SK_pr))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Secrecy properties for initial child of IKE_SA ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defgoal ikev2_psk
  (forall 
  ((SPI_init n_init SPI_resp n_resp data)(ppk skey)(gr base)(i rndx)(z z-0 strd))
  (implies 
    (and 
      (p "init-rc" z 4)
      (p "init-rc" "SPI_init" z SPI_init)
      (p "init-rc" "SPI_resp" z SPI_resp)
      (p "init-rc" "n_init" z n_init)
      (p "init-rc" "n_resp" z n_resp)  
      (p "init-rc" "ppk" z ppk)
      (p "init-rc" "gr" z gr)
      (p "init-rc" "i" z i)
      (p "" z-0 1)
      (p "" "x" z-0 (initialChild_KEYMAT (exp gr i)) )
    )
    (false))
  )
  (comment Probe confidentiality of key material that generates keys in initial child from IKE_SA child))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Secrecy properties for rekeyed IKE_SA ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;
;; rekey then child
(defgoal ikev2_psk
  (forall 
    ((SPI_init n_init SPI_resp n_resp SPIrk_init SPIrk_resp nrk_init nrk_resp data)(ppk skey)(gr grkr base)(i rki rndx)(z z-0 strd))
  (implies 
    (and 
      (p "init-rc" z 6)
      (p "init-rc" "SPI_init" z SPI_init)
      (p "init-rc" "SPI_resp" z SPI_resp)
      (p "init-rc" "n_init" z n_init)
      (p "init-rc" "n_resp" z n_resp)  
      (p "init-rc" "ppk" z ppk)
      (p "init-rc" "gr" z gr)
      (p "init-rc" "i" z i)
      (p "init-rc" "SPIrk_init" z SPIrk_init)
      (p "init-rc" "SPIrk_resp" z SPIrk_resp)
      (p "init-rc" "nrk_init" z nrk_init)
      (p "init-rc" "nrk_resp" z nrk_resp) 
      (p "init-rc" "grkr" z grkr)
      (p "init-rc" "rki" z rki)
      (p "" z-0 1)
      (p "" "x" z-0 (rekey_SK_ai (exp gr i) (exp grkr rki)))
    )
    (false))
  )
  (comment Probe confidentiality of rekey_SK_ai))

(defgoal ikev2_psk
  (forall 
    ((SPI_init n_init SPI_resp n_resp SPIrk_init SPIrk_resp nrk_init nrk_resp data)(ppk skey)(gr grkr base)(i rki rndx)(z z-0 strd))
  (implies 
    (and 
      (p "init-rc" z 6)
      (p "init-rc" "SPI_init" z SPI_init)
      (p "init-rc" "SPI_resp" z SPI_resp)
      (p "init-rc" "n_init" z n_init)
      (p "init-rc" "n_resp" z n_resp)  
      (p "init-rc" "ppk" z ppk)
      (p "init-rc" "gr" z gr)
      (p "init-rc" "i" z i)
      (p "init-rc" "SPIrk_init" z SPIrk_init)
      (p "init-rc" "SPIrk_resp" z SPIrk_resp)
      (p "init-rc" "nrk_init" z nrk_init)
      (p "init-rc" "nrk_resp" z nrk_resp) 
      (p "init-rc" "grkr" z grkr)
      (p "init-rc" "rki" z rki)
      (p "" z-0 1)
      (p "" "x" z-0 (rekey_SK_ar (exp gr i) (exp grkr rki)))
    )
    (false))
  )
  (comment Probe confidentiality of rekey_SK_ar))

(defgoal ikev2_psk
  (forall 
    ((SPI_init n_init SPI_resp n_resp SPIrk_init SPIrk_resp nrk_init nrk_resp data)(ppk skey)(gr grkr base)(i rki rndx)(z z-0 strd))
  (implies 
    (and 
      (p "init-rc" z 6)
      (p "init-rc" "SPI_init" z SPI_init)
      (p "init-rc" "SPI_resp" z SPI_resp)
      (p "init-rc" "n_init" z n_init)
      (p "init-rc" "n_resp" z n_resp)  
      (p "init-rc" "ppk" z ppk)
      (p "init-rc" "gr" z gr)
      (p "init-rc" "i" z i)
      (p "init-rc" "SPIrk_init" z SPIrk_init)
      (p "init-rc" "SPIrk_resp" z SPIrk_resp)
      (p "init-rc" "nrk_init" z nrk_init)
      (p "init-rc" "nrk_resp" z nrk_resp) 
      (p "init-rc" "grkr" z grkr)
      (p "init-rc" "rki" z rki)
      (p "" z-0 1)
      (p "" "x" z-0 (rekey_SK_ei (exp gr i) (exp grkr rki)))
    )
    (false))
  )
  (comment Probe confidentiality of rekey_SK_ei))

(defgoal ikev2_psk
  (forall 
    ((SPI_init n_init SPI_resp n_resp SPIrk_init SPIrk_resp nrk_init nrk_resp data)(ppk skey)(gr grkr base)(i rki rndx)(z z-0 strd))
  (implies 
    (and 
      (p "init-rc" z 6)
      (p "init-rc" "SPI_init" z SPI_init)
      (p "init-rc" "SPI_resp" z SPI_resp)
      (p "init-rc" "n_init" z n_init)
      (p "init-rc" "n_resp" z n_resp)  
      (p "init-rc" "ppk" z ppk)
      (p "init-rc" "gr" z gr)
      (p "init-rc" "i" z i)
      (p "init-rc" "SPIrk_init" z SPIrk_init)
      (p "init-rc" "SPIrk_resp" z SPIrk_resp)
      (p "init-rc" "nrk_init" z nrk_init)
      (p "init-rc" "nrk_resp" z nrk_resp) 
      (p "init-rc" "grkr" z grkr)
      (p "init-rc" "rki" z rki)
      (p "" z-0 1)
      (p "" "x" z-0 (rekey_SK_er (exp gr i) (exp grkr rki)))
    )
    (false))
  )
  (comment Probe confidentiality of rekey_SK_er))

(defgoal ikev2_psk
  (forall 
    ((SPI_init n_init SPI_resp n_resp SPIrk_init SPIrk_resp nrk_init nrk_resp data)(ppk skey)(gr grkr base)(i rki rndx)(z z-0 strd))
  (implies 
    (and 
      (p "init-rc" z 6)
      (p "init-rc" "SPI_init" z SPI_init)
      (p "init-rc" "SPI_resp" z SPI_resp)
      (p "init-rc" "n_init" z n_init)
      (p "init-rc" "n_resp" z n_resp)  
      (p "init-rc" "ppk" z ppk)
      (p "init-rc" "gr" z gr)
      (p "init-rc" "i" z i)
      (p "init-rc" "SPIrk_init" z SPIrk_init)
      (p "init-rc" "SPIrk_resp" z SPIrk_resp)
      (p "init-rc" "nrk_init" z nrk_init)
      (p "init-rc" "nrk_resp" z nrk_resp) 
      (p "init-rc" "grkr" z grkr)
      (p "init-rc" "rki" z rki)
      (p "" z-0 1)
      (p "" "x" z-0 (rekey_SK_d (exp gr i) (exp grkr rki)))
    )
    (false))
  )
  (comment Probe confidentiality of rekey_SK_d))

;; child then rekey
(defgoal ikev2_psk
  (forall 
    ((SPI_init n_init SPI_resp n_resp SPIrk_init SPIrk_resp nrk_init nrk_resp data)(ppk skey)(gr grkr base)(i rki rndx)(z z-0 strd))
  (implies 
    (and 
      (p "init-cr" z 8)
      (p "init-cr" "SPI_init" z SPI_init)
      (p "init-cr" "SPI_resp" z SPI_resp)
      (p "init-cr" "n_init" z n_init)
      (p "init-cr" "n_resp" z n_resp)  
      (p "init-cr" "ppk" z ppk)
      (p "init-cr" "gr" z gr)
      (p "init-cr" "i" z i)
      (p "init-cr" "SPIrk_init" z SPIrk_init)
      (p "init-cr" "SPIrk_resp" z SPIrk_resp)
      (p "init-cr" "nrk_init" z nrk_init)
      (p "init-cr" "nrk_resp" z nrk_resp) 
      (p "init-cr" "grkr" z grkr)
      (p "init-cr" "rki" z rki)
      (p "" z-0 1)
      (p "" "x" z-0 (rekey_SK_ai (exp gr i) (exp grkr rki)))
    )
    (false))
  )
  (comment Probe confidentiality of rekey_SK_ai))

(defgoal ikev2_psk
  (forall 
    ((SPI_init n_init SPI_resp n_resp SPIrk_init SPIrk_resp nrk_init nrk_resp data)(ppk skey)(gr grkr base)(i rki rndx)(z z-0 strd))
  (implies 
    (and 
      (p "init-cr" z 8)
      (p "init-cr" "SPI_init" z SPI_init)
      (p "init-cr" "SPI_resp" z SPI_resp)
      (p "init-cr" "n_init" z n_init)
      (p "init-cr" "n_resp" z n_resp)  
      (p "init-cr" "ppk" z ppk)
      (p "init-cr" "gr" z gr)
      (p "init-cr" "i" z i)
      (p "init-cr" "SPIrk_init" z SPIrk_init)
      (p "init-cr" "SPIrk_resp" z SPIrk_resp)
      (p "init-cr" "nrk_init" z nrk_init)
      (p "init-cr" "nrk_resp" z nrk_resp) 
      (p "init-cr" "grkr" z grkr)
      (p "init-cr" "rki" z rki)
      (p "" z-0 1)
      (p "" "x" z-0 (rekey_SK_ar (exp gr i) (exp grkr rki)))
    )
    (false))
  )
  (comment Probe confidentiality of rekey_SK_ar))

(defgoal ikev2_psk
  (forall 
    ((SPI_init n_init SPI_resp n_resp SPIrk_init SPIrk_resp nrk_init nrk_resp data)(ppk skey)(gr grkr base)(i rki rndx)(z z-0 strd))
  (implies 
    (and 
      (p "init-cr" z 8)
      (p "init-cr" "SPI_init" z SPI_init)
      (p "init-cr" "SPI_resp" z SPI_resp)
      (p "init-cr" "n_init" z n_init)
      (p "init-cr" "n_resp" z n_resp)  
      (p "init-cr" "ppk" z ppk)
      (p "init-cr" "gr" z gr)
      (p "init-cr" "i" z i)
      (p "init-cr" "SPIrk_init" z SPIrk_init)
      (p "init-cr" "SPIrk_resp" z SPIrk_resp)
      (p "init-cr" "nrk_init" z nrk_init)
      (p "init-cr" "nrk_resp" z nrk_resp) 
      (p "init-cr" "grkr" z grkr)
      (p "init-cr" "rki" z rki)
      (p "" z-0 1)
      (p "" "x" z-0 (rekey_SK_ei (exp gr i) (exp grkr rki)))
    )
    (false))
  )
  (comment Probe confidentiality of rekey_SK_ei))

(defgoal ikev2_psk
  (forall 
    ((SPI_init n_init SPI_resp n_resp SPIrk_init SPIrk_resp nrk_init nrk_resp data)(ppk skey)(gr grkr base)(i rki rndx)(z z-0 strd))
  (implies 
    (and 
      (p "init-cr" z 8)
      (p "init-cr" "SPI_init" z SPI_init)
      (p "init-cr" "SPI_resp" z SPI_resp)
      (p "init-cr" "n_init" z n_init)
      (p "init-cr" "n_resp" z n_resp)  
      (p "init-cr" "ppk" z ppk)
      (p "init-cr" "gr" z gr)
      (p "init-cr" "i" z i)
      (p "init-cr" "SPIrk_init" z SPIrk_init)
      (p "init-cr" "SPIrk_resp" z SPIrk_resp)
      (p "init-cr" "nrk_init" z nrk_init)
      (p "init-cr" "nrk_resp" z nrk_resp) 
      (p "init-cr" "grkr" z grkr)
      (p "init-cr" "rki" z rki)
      (p "" z-0 1)
      (p "" "x" z-0 (rekey_SK_er (exp gr i) (exp grkr rki)))
    )
    (false))
  )
  (comment Probe confidentiality of rekey_SK_er))

(defgoal ikev2_psk
  (forall 
    ((SPI_init n_init SPI_resp n_resp SPIrk_init SPIrk_resp nrk_init nrk_resp data)(ppk skey)(gr grkr base)(i rki rndx)(z z-0 strd))
  (implies 
    (and 
      (p "init-cr" z 8)
      (p "init-cr" "SPI_init" z SPI_init)
      (p "init-cr" "SPI_resp" z SPI_resp)
      (p "init-cr" "n_init" z n_init)
      (p "init-cr" "n_resp" z n_resp)  
      (p "init-cr" "ppk" z ppk)
      (p "init-cr" "gr" z gr)
      (p "init-cr" "i" z i)
      (p "init-cr" "SPIrk_init" z SPIrk_init)
      (p "init-cr" "SPIrk_resp" z SPIrk_resp)
      (p "init-cr" "nrk_init" z nrk_init)
      (p "init-cr" "nrk_resp" z nrk_resp) 
      (p "init-cr" "grkr" z grkr)
      (p "init-cr" "rki" z rki)
      (p "" z-0 1)
      (p "" "x" z-0 (rekey_SK_d (exp gr i) (exp grkr rki)))
    )
    (false))
  )
  (comment Probe confidentiality of rekey_SK_d))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Secrecy properties for Child_SA ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
(defgoal ikev2_psk
  (forall 
    ((SPI_init n_init SPI_resp n_resp ncc_init ncc_resp data)(ppk skey)(gr gccr base)(i cci rndx)(z z-0 strd))
  (implies 
    (and 
      (p "init-cr" z 6)
      (p "init-cr" "SPI_init" z SPI_init)
      (p "init-cr" "SPI_resp" z SPI_resp)
      (p "init-cr" "n_init" z n_init)
      (p "init-cr" "n_resp" z n_resp)  
      (p "init-cr" "ppk" z ppk)
      (p "init-cr" "gr" z gr)
      (p "init-cr" "i" z i)
      (p "init-cr" "ncc_init" z ncc_init)
      (p "init-cr" "ncc_resp" z ncc_resp) 
      (p "init-cr" "gccr" z gccr)
      (p "init-cr" "cci" z cci)
      (p "" z-0 1)
      (p "" "x" z-0 (child_KEYMAT (SK_d (exp gr i)) (exp gccr cci)))
    )
    (false))
  )
  (comment Probe confidentiality of child_KEYMAT for child-then-rekey ))

(defgoal ikev2_psk
  (forall 
    ((SPI_init n_init SPI_resp n_resp SPIrk_init SPIrk_resp nrk_init nrk_resp ncc_init ncc_resp data)(ppk skey)(gr grkr gccr base)(i rki cci rndx)(z z-0 strd))
  (implies 
    (and 
      (p "init-rc" z 8)
      (p "init-rc" "SPI_init" z SPI_init)
      (p "init-rc" "SPI_resp" z SPI_resp)
      (p "init-rc" "n_init" z n_init)
      (p "init-rc" "n_resp" z n_resp)  
      (p "init-rc" "ppk" z ppk)
      (p "init-rc" "gr" z gr)
      (p "init-rc" "i" z i)
      (p "init-rc" "SPIrk_init" z SPIrk_init)
      (p "init-rc" "SPIrk_resp" z SPIrk_resp)
      (p "init-rc" "nrk_init" z nrk_init)
      (p "init-rc" "nrk_resp" z nrk_resp) 
      (p "init-rc" "grkr" z grkr)
      (p "init-rc" "rki" z rki)
      (p "init-rc" "ncc_init" z ncc_init)
      (p "init-rc" "ncc_resp" z ncc_resp) 
      (p "init-rc" "gccr" z gccr)
      (p "init-rc" "cci" z cci)      
      (p "" z-0 1)
      (p "" "x" z-0 (child_KEYMAT (rekey_SK_d (exp gr i) (exp grkr rki)) (exp gccr cci)))
    )
    (false))
  )
  (comment Probe confidentiality of child_KEYMAT for rekey-then-child))












SECRECY ENDCOMMENT)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Authentication Goals     ;;
;; for security association ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; Aliveness --> weak agreement --> non-injective agreement --> injective agreement

;; QUESTION how to make injective?
;; The following defgoal verifies non-injective agreement of both the IKE_SA and initial CHILD_SA from the initiator's perspective, up to the possible disagreement of SPI_init2 and SPI_resp2
(defgoal ikev2_psk
  (forall
    ((SPI_init SPI_resp n_init n_resp SPI_init2 SPI_resp2 data) (psk ppk skey) (ID_init id_ppk ID_resp name)
      (i r rndx) (z strd))
    (implies
      (and (p "init-rc" z 4) 
        (p "init-rc" "SPI_init" z SPI_init)
        (p "init-rc" "SPI_resp" z SPI_resp)
        (p "init-rc" "n_init" z n_init)
        (p "init-rc" "n_resp" z n_resp)
        (p "init-rc" "SPI_init2" z SPI_init2)
        (p "init-rc" "SPI_resp2" z SPI_resp2)
        (p "init-rc" "psk" z psk)
        (p "init-rc" "ppk" z ppk) 
        (p "init-rc" "ID_init" z ID_init)
        (p "init-rc" "ID_resp" z ID_resp)
        (p "init-rc" "id_ppk" z id_ppk)
        (p "init-rc" "gr" z (exp (gen) r))
        (p "init-rc" "i" z i)
        (non psk)
        (non ppk) (ugen SPI_init) (ugen n_init) (ugen SPI_init2)
      )
      (or
        (exists
            ((SPI_init2-0 SPI_resp2-0 data)  (z-0 strd))
            (and (p "resp-rc" z-0 4) 
                (p "resp-rc" "SPI_init" z-0 SPI_init)
                (p "resp-rc" "SPI_resp" z-0 SPI_resp)
                (p "resp-rc" "n_init" z-0 n_init)
                (p "resp-rc" "n_resp" z-0 n_resp)
                (p "resp-rc" "SPI_init2" z-0 SPI_init2-0)
                (p "resp-rc" "SPI_resp2" z-0 SPI_resp2-0)
                (p "resp-rc" "psk" z-0 psk) 
                (p "resp-rc" "ppk" z-0 ppk)
                (p "resp-rc" "ID_init" z-0 ID_init)
                (p "resp-rc" "ID_resp" z-0 ID_resp)
                (p "resp-rc" "id_ppk" z-0 id_ppk)
                (p "resp-rc" "gi" z-0 (exp (gen) i))
                (p "resp-rc" "r" z-0 r) 
                (prec z 0 z-0 0) (prec z 2 z-0 2)
                (prec z-0 1 z 1) (prec z-0 3 z 3) 
                (ugen SPI_resp) (ugen n_resp) 
                (ugen SPI_resp2-0) (fact peerID z ID_resp)
                (fact pskIDs psk ID_init ID_resp)
                (fact isKeyIDFor id_ppk ppk)
            )
        )
        (exists
            ((SPI_init2-0 SPI_resp2-0 data)  (z-0 strd))
            (and (p "resp-cr" z-0 4) 
                (p "resp-cr" "SPI_init" z-0 SPI_init)
                (p "resp-cr" "SPI_resp" z-0 SPI_resp)
                (p "resp-cr" "n_init" z-0 n_init)
                (p "resp-cr" "n_resp" z-0 n_resp)
                (p "resp-cr" "SPI_init2" z-0 SPI_init2-0)
                (p "resp-cr" "SPI_resp2" z-0 SPI_resp2-0)
                (p "resp-cr" "psk" z-0 psk) 
                (p "resp-cr" "ppk" z-0 ppk)
                (p "resp-cr" "ID_init" z-0 ID_init)
                (p "resp-cr" "ID_resp" z-0 ID_resp)
                (p "resp-cr" "id_ppk" z-0 id_ppk)
                (p "resp-cr" "gi" z-0 (exp (gen) i))
                (p "resp-cr" "r" z-0 r) 
                (prec z 0 z-0 0) (prec z 2 z-0 2)
                (prec z-0 1 z 1) (prec z-0 3 z 3) 
                (ugen SPI_resp) (ugen n_resp) 
                (ugen SPI_resp2-0) (fact peerID z ID_resp)
                (fact pskIDs psk ID_init ID_resp)
                (fact isKeyIDFor id_ppk ppk)
            )
        )
      ))))
    



;;;;;;;;;;;;;;;;;;;;;;;;;;




;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Authentication Goals ;;
;; for rekeying         ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;

;; non-aliveness of rekey protocol before create child, assuming that Initiator and responder share an IKE_SA 
(defgoal ikev2_psk ; Rekey aliveness from init-rc's persepctive
  (forall
    ((ID_resp name)(z strd))
  (implies
    ;predicate: init-rc completes the rekeying process with someone who is ID_resp...
    (and
      (p "init-rc" z 6)
      (p "init-rc" "ID_resp" z ID_resp))
    ;concl; ...and that ID_resp is aware that rekeying is going on
    (or 
    (exists ((z-0 strd))
            (and (p "resp-rc" z-0 5)
                 (p "resp-rc" "ID_resp" z-0 ID_resp)))
    (exists ((z-0 strd))
            (and (p "resp-cr" z-0 7)
                 (p "resp-cr" "ID_resp" z-0 ID_resp)))

  )))
  (comment "Aliveness when rekeying with resp-rc or resp-cr from perspective of init-rc"))

(defgoal ikev2_psk ; Rekey aliveness from init-cr's persepctive
  (forall
    ((ID_resp name)(z strd))
  (implies
    ;predicate: init-cr completes the rekeying process with someone who is ID_resp...
    (and
      (p "init-cr" z 8)
      (p "init-cr" "ID_resp" z ID_resp))
    ;concl; ...and that ID_resp is aware that rekeying is going on
    (or 
      (exists ((z-0 strd))
            (and (p "resp-rc" z-0 5)
                 (p "resp-rc" "ID_resp" z-0 ID_resp)))
      (exists ((z-0 strd))
            (and (p "resp-cr" z-0 7)
                 (p "resp-cr" "ID_resp" z-0 ID_resp)))

  )))
  (comment "Aliveness when rekeying with resp-rc or resp-cr from perspective of init-cr"))




;; Aliveness from resp's perspective

(defgoal ikev2_psk ; Rekey aliveness from resp-rc's perspective
  (forall
    ((ID_init name)(z strd))
  (implies
    (and
      (p "resp-rc" z 6)
      (p "resp-rc" "ID_init" z ID_init))
    (or
      (exists ((z-0 strd))
            (and (p "init-rc" z-0 5)
                 (p "init-rc" "ID_init" z-0 ID_init)))
      (exists ((z-0 strd))
            (and (p "init-cr" z-0 7)
                 (p "init-cr" "ID_init" z-0 ID_init)))
    )
  ))
  (comment "Aliveness when rekeying with init-rc from perspective of resp-rc"))



(defgoal ikev2_psk ; Rekey aliveness from resp-cr's perspective
  (forall
    ((ID_init name)(z strd))
  (implies
    (and
      (p "resp-cr" z 8)
      (p "resp-cr" "ID_init" z ID_init))
    (or   
      (exists ((z-0 strd))
            (and (p "init-rc" z-0 5)
                 (p "init-rc" "ID_init" z-0 ID_init)))
      (exists ((z-0 strd))
            (and (p "init-cr" z-0 7)
                 (p "init-cr" "ID_init" z-0 ID_init)))
    )
  ))
  (comment "Aliveness when rekeying with init-rc from perspective of resp-cr"))



;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Authentication Goals ;;
;; for create child     ;;
;;;;;;;;;;;;;;;;;;;;;;;;;;

(defgoal ikev2_psk ; Non-aliveness when create child before rekeying from init-cr's persepctive
  (forall
    ((ID_resp name)(z strd))
  (implies
    ;predicate: init-cr completes the rekeying process with someone who is ID_resp...
    (and
      (p "init-cr" z 6)
      (p "init-cr" "ID_resp" z ID_resp))
    ;concl; ...and that ID_resp is aware that rekeying is going on
    (or 
      (exists ((z-0 strd))
            (and (p "resp-rc" z-0 7)
                 (p "resp-rc" "ID_resp" z-0 ID_resp)))
      (exists ((z-0 strd))
            (and (p "resp-cr" z-0 5)
                 (p "resp-cr" "ID_resp" z-0 ID_resp)))

  )))
  (comment "Non-aliveness when create child before rekeying from init-cr's perspective"))



(defgoal ikev2_psk ; Non-aliveness of create child before rekey from resp-cr's perspective
  (forall
    ((ID_init name)(z strd))
  (implies
    (and
      (p "resp-cr" z 6)
      (p "resp-cr" "ID_init" z ID_init))
    (or   
      (exists ((z-0 strd))
            (and (p "init-rc" z-0 7)
                 (p "init-rc" "ID_init" z-0 ID_init)))
      (exists ((z-0 strd))
            (and (p "init-cr" z-0 5)
                 (p "init-cr" "ID_init" z-0 ID_init)))
    )
  ))
  (comment "Aliveness when rekeying with init-rc from perspective of resp-cr"))
  
  ;; aliveness of rekey then create-child

;; if the initiator rekeys then creates a child, then the responder also rekeys and creates a child, although the spis of the initial child don't match
(defgoal ikev2_psk; weak agreement of rekey then create child from init-rc's perspective, as long as we're willing to have different SPIs
  (forall
    ((SPI_init SPI_resp n_init n_resp SPI_init2 SPI_resp2 nrk_init
       nrk_resp SPIrk_init SPIrk_resp SPIcc_init SPIcc_resp ncc_init
       ncc_resp data) (psk ppk skey) (ID_init id_ppk ID_resp name)
      (i rki cci r rkr ccr rndx) (z strd))
    (implies
      (and (p "init-rc" z 8) 
        (p "init-rc" "SPI_init" z SPI_init)
        (p "init-rc" "SPI_resp" z SPI_resp)
        (p "init-rc" "n_init" z n_init) 
        (p "init-rc" "n_resp" z n_resp)
        (p "init-rc" "SPI_init2" z SPI_init2)
        (p "init-rc" "SPI_resp2" z SPI_resp2)
        (p "init-rc" "nrk_init" z nrk_init)
        (p "init-rc" "nrk_resp" z nrk_resp)
        (p "init-rc" "SPIrk_init" z SPIrk_init)
        (p "init-rc" "SPIrk_resp" z SPIrk_resp)
        (p "init-rc" "SPIcc_init" z SPIcc_init)
        (p "init-rc" "SPIcc_resp" z SPIcc_resp)
        (p "init-rc" "ncc_init" z ncc_init)
        (p "init-rc" "ncc_resp" z ncc_resp) 
        (p "init-rc" "psk" z psk)
        (p "init-rc" "ppk" z ppk) 
        (p "init-rc" "ID_init" z ID_init)
        (p "init-rc" "ID_resp" z ID_resp)
        (p "init-rc" "id_ppk" z id_ppk)
        (p "init-rc" "gr" z (exp (gen) r))
        (p "init-rc" "grkr" z (exp (gen) rkr))
        (p "init-rc" "gccr" z (exp (gen) ccr)) 
        (p "init-rc" "i" z i)
        (p "init-rc" "rki" z rki) 
        (p "init-rc" "cci" z cci) (non psk)
        (non ppk) (ugen SPI_init) (ugen n_init) (ugen SPI_init2)
        (ugen nrk_init) (ugen SPIrk_init) (ugen SPIcc_init)
        (ugen ncc_init))
      (exists ((SPI_init2-0 SPI_resp2-0 data) (rkr-0 rndx) (z-0 strd))
        (and (p "resp-rc" z-0 8) 
          (p "resp-rc" "SPI_init" z-0 SPI_init)
          (p "resp-rc" "SPI_resp" z-0 SPI_resp)
          (p "resp-rc" "n_init" z-0 n_init)
          (p "resp-rc" "n_resp" z-0 n_resp)
          (p "resp-rc" "SPI_init2" z-0 SPI_init2-0) ;***
          (p "resp-rc" "SPI_resp2" z-0 SPI_resp2-0) ;***
          (p "resp-rc" "nrk_init" z-0 nrk_init)
          (p "resp-rc" "nrk_resp" z-0 nrk_resp)
          (p "resp-rc" "SPIrk_init" z-0 SPIrk_init)
          (p "resp-rc" "SPIrk_resp" z-0 SPIrk_resp)
          (p "resp-rc" "SPIcc_init" z-0 SPIcc_init)
          (p "resp-rc" "SPIcc_resp" z-0 SPIcc_resp)
          (p "resp-rc" "ncc_init" z-0 ncc_init)
          (p "resp-rc" "ncc_resp" z-0 ncc_resp)
          (p "resp-rc" "psk" z-0 psk) 
          (p "resp-rc" "ppk" z-0 ppk)
          (p "resp-rc" "ID_init" z-0 ID_init)
          (p "resp-rc" "ID_resp" z-0 ID_resp)
          (p "resp-rc" "id_ppk" z-0 id_ppk)
          (p "resp-rc" "gi" z-0 (exp (gen) i))
          (p "resp-rc" "grki" z-0 (exp (gen) (mul rki rkr (rec rkr-0))))
          (p "resp-rc" "gcci" z-0 (exp (gen) cci))
          (p "resp-rc" "r" z-0 r)
           (p "resp-rc" "rkr" z-0 rkr-0)
          (p "resp-rc" "ccr" z-0 ccr) 
          (prec z 0 z-0 0) 
          (prec z 2 z-0 2)
          (prec z 4 z-0 4) (prec z 6 z-0 6) (prec z-0 1 z 1)
          (prec z-0 3 z 3) (prec z-0 5 z 5) (prec z-0 7 z 7)
          (ugen SPI_resp) (ugen n_resp) (ugen nrk_resp)
          (ugen SPIrk_resp) (ugen SPIcc_resp) (ugen ncc_resp)
          (ugen SPI_resp2-0) (fact peerID z ID_resp)
          (fact pskIDs psk ID_init ID_resp)
          (fact isKeyIDFor id_ppk ppk))))))

;; QUESTION --> why is it not interpreting multiplicative inverses cirrectky
(defgoal ikev2_psk; weak agreement of rekey then create child from resp-rc's perspective, as long as we're willing to have different SPIs
  (forall
    ((SPI_init SPI_resp n_init n_resp SPI_init2 SPI_resp2 nrk_init
       nrk_resp SPIrk_init SPIrk_resp SPIcc_init SPIcc_resp ncc_init
       ncc_resp data) (psk ppk skey) (ID_init id_ppk ID_resp name)
      (i rki cci r rkr ccr rndx) (z strd))
    (implies
      (and (p "resp-rc" z 8) 
        (p "resp-rc" "SPI_init" z SPI_init)
        (p "resp-rc" "SPI_resp" z SPI_resp)
        (p "resp-rc" "n_init" z n_init) 
        (p "resp-rc" "n_resp" z n_resp)
        (p "resp-rc" "SPI_init2" z SPI_init2)
        (p "resp-rc" "SPI_resp2" z SPI_resp2)
        (p "resp-rc" "nrk_init" z nrk_init)
        (p "resp-rc" "nrk_resp" z nrk_resp)
        (p "resp-rc" "SPIrk_init" z SPIrk_init)
        (p "resp-rc" "SPIrk_resp" z SPIrk_resp)
        (p "resp-rc" "SPIcc_init" z SPIcc_init)
        (p "resp-rc" "SPIcc_resp" z SPIcc_resp)
        (p "resp-rc" "ncc_init" z ncc_init)
        (p "resp-rc" "ncc_resp" z ncc_resp) 
        (p "resp-rc" "psk" z psk)
        (p "resp-rc" "ppk" z ppk) 
        (p "resp-rc" "ID_init" z ID_init)
        (p "resp-rc" "ID_resp" z ID_resp)
        (p "resp-rc" "id_ppk" z id_ppk)
        (p "resp-rc" "gi" z (exp (gen) i))
        (p "resp-rc" "grki" z (exp (gen) rki))
        (p "resp-rc" "gcci" z (exp (gen) cci)) 
        (p "resp-rc" "r" z r)
        (p "resp-rc" "rkr" z rkr) 
        (p "resp-rc" "ccr" z ccr) (non psk)
        (non ppk) (ugen SPI_resp) (ugen n_resp) (ugen SPI_resp2)
        (ugen nrk_resp) (ugen SPIrk_resp) (ugen SPIcc_resp)
        (ugen ncc_resp))
      (exists ((SPI_init2-0 SPI_resp2-0 data) (z-0 strd))
        (and (p "init-rc" z-0 7) 
          (p "init-rc" "SPI_init" z-0 SPI_init)
          (p "init-rc" "SPI_resp" z-0 SPI_resp)
          (p "init-rc" "n_init" z-0 n_init)
          (p "init-rc" "n_resp" z-0 n_resp)
          (p "init-rc" "SPI_init2" z-0 SPI_init2-0) ;***
          (p "init-rc" "SPI_resp2" z-0 SPI_resp2-0) ;***
          (p "init-rc" "nrk_init" z-0 nrk_init)
          (p "init-rc" "nrk_resp" z-0 nrk_resp)
          (p "init-rc" "SPIrk_init" z-0 SPIrk_init)
          (p "init-rc" "SPIrk_resp" z-0 SPIrk_resp)
          (p "init-rc" "SPIcc_init" z-0 SPIcc_init)
          (p "init-rc" "SPIcc_resp" z-0 SPIcc_resp)
          (p "init-rc" "ncc_init" z-0 ncc_init)
          (p "init-rc" "ncc_resp" z-0 ncc_resp)
          (p "init-rc" "psk" z-0 psk) 
          (p "init-rc" "ppk" z-0 ppk)
          (p "init-rc" "ID_init" z-0 ID_init)
          (p "init-rc" "ID_resp" z-0 ID_resp)
          (p "init-rc" "id_ppk" z-0 id_ppk)
          (p "init-rc" "gr" z-0 (exp (gen) r))
          (p "init-rc" "grkr" z-0 (exp (gen) rkr))
          (p "init-rc" "gccr" z-0 (exp (gen) ccr))
          (p "init-rc" "i" z-0 i)
           (p "init-rc" "rki" z-0 rki)
          (p "init-rc" "cci" z-0 cci) 
          ;(ugen SPI_init) (ugen n_init) (ugen nrk_init)(ugen SPIrk_init) (ugen SPIcc_init) (ugen ncc_init)         (ugen SPI_init2-0) 
          (fact peerID z ID_init)
          (fact pskIDs psk ID_init ID_resp)
          (fact isKeyIDFor id_ppk ppk))))))


(defgoal ikev2_psk; weak agreement of rekey then create child from resp-rc's perspective, as long as we're willing to have different SPIs
  (forall
    ((SPI_init SPI_resp n_init n_resp SPI_init2 SPI_resp2 nrk_init
       nrk_resp SPIrk_init SPIrk_resp SPIcc_init SPIcc_resp ncc_init
       ncc_resp data) (psk ppk skey) (ID_init id_ppk ID_resp name)
      (i cci r rki rkr ccr rndx) (z strd))
    (implies
      (and (p "resp-rc" z 8) 
        (p "resp-rc" "SPI_init" z SPI_init)
        (p "resp-rc" "SPI_resp" z SPI_resp)
        (p "resp-rc" "n_init" z n_init) 
        (p "resp-rc" "n_resp" z n_resp)
        (p "resp-rc" "SPI_init2" z SPI_init2)
        (p "resp-rc" "SPI_resp2" z SPI_resp2)
        (p "resp-rc" "nrk_init" z nrk_init)
        (p "resp-rc" "nrk_resp" z nrk_resp)
        (p "resp-rc" "SPIrk_init" z SPIrk_init)
        (p "resp-rc" "SPIrk_resp" z SPIrk_resp)
        (p "resp-rc" "SPIcc_init" z SPIcc_init)
        (p "resp-rc" "SPIcc_resp" z SPIcc_resp)
        (p "resp-rc" "ncc_init" z ncc_init)
        (p "resp-rc" "ncc_resp" z ncc_resp) 
        (p "resp-rc" "psk" z psk)
        (p "resp-rc" "ppk" z ppk) 
        (p "resp-rc" "ID_init" z ID_init)
        (p "resp-rc" "ID_resp" z ID_resp)
        (p "resp-rc" "id_ppk" z id_ppk)
        (p "resp-rc" "gi" z (exp (gen) i))
        (p "resp-rc" "grki" z (exp (gen) rki))
        (p "resp-rc" "gcci" z (exp (gen) cci)) 
        (p "resp-rc" "r" z r)
        (p "resp-rc" "rkr" z rkr) 
        (p "resp-rc" "ccr" z ccr) (non psk)
        (non ppk) (ugen SPI_resp) (ugen n_resp) (ugen SPI_resp2)
        (ugen nrk_resp) (ugen SPIrk_resp) (ugen SPIcc_resp)
        (ugen ncc_resp))
      (exists ((SPI_init2-0 SPI_resp2-0 data) (z-0 strd) )
        (and (p "init-rc" z-0 7) 
          (p "init-rc" "SPI_init" z-0 SPI_init)
          (p "init-rc" "SPI_resp" z-0 SPI_resp)
          (p "init-rc" "n_init" z-0 n_init)
          (p "init-rc" "n_resp" z-0 n_resp)
          (p "init-rc" "SPI_init2" z-0 SPI_init2-0) ;***
          (p "init-rc" "SPI_resp2" z-0 SPI_resp2-0) ;***
          (p "init-rc" "nrk_init" z-0 nrk_init)
          (p "init-rc" "nrk_resp" z-0 nrk_resp)
          (p "init-rc" "SPIrk_init" z-0 SPIrk_init)
          (p "init-rc" "SPIrk_resp" z-0 SPIrk_resp)
          (p "init-rc" "SPIcc_init" z-0 SPIcc_init)
          (p "init-rc" "SPIcc_resp" z-0 SPIcc_resp)
          (p "init-rc" "ncc_init" z-0 ncc_init)
          (p "init-rc" "ncc_resp" z-0 ncc_resp)
          (p "init-rc" "psk" z-0 psk) 
          (p "init-rc" "ppk" z-0 ppk)
          (p "init-rc" "ID_init" z-0 ID_init)
          (p "init-rc" "ID_resp" z-0 ID_resp)
          (p "init-rc" "id_ppk" z-0 id_ppk)
          (p "init-rc" "gr" z-0 (exp (gen) r))
;          (p "init-rc" "grkr" z-0 (exp (gen) rkr))
          (p "init-rc" "gccr" z-0 (exp (gen) ccr))
          (p "init-rc" "i" z-0 i)
;           (p "init-rc" "rki" z-0 rki)
          (p "init-rc" "cci" z-0 cci) 
          ;(ugen SPI_init) (ugen n_init) (ugen nrk_init)(ugen SPIrk_init) (ugen SPIcc_init) (ugen ncc_init)         (ugen SPI_init2-0) 
          (fact peerID z ID_init)
          (fact pskIDs psk ID_init ID_resp)
          (fact isKeyIDFor id_ppk ppk))))))
