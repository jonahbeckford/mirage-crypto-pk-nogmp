[@@@warning "-27-32-33-34-37-69"]

module Z = struct
  type t = string
end

let unsupported what =
  failwith
    ("unsupported: " ^ what
   ^ " needs big-number arithmetic, and this build of mirage-crypto-pk has none; use ECDSA or \
      Ed25519 certificates and ECDHE")

let no_rsa = Error (`Msg "RSA is not supported by this build of mirage-crypto-pk (no arithmetic)")

module Rsa = struct
  exception Insufficient_key

  type pub = { e : Z.t; n : Z.t }

  let pub ~e ~n = no_rsa

  type priv = {
    e : Z.t;
    d : Z.t;
    n : Z.t;
    p : Z.t;
    q : Z.t;
    dp : Z.t;
    dq : Z.t;
    q' : Z.t;
  }

  let priv ~e ~d ~n ~p ~q ~dp ~dq ~q' = no_rsa
  let pub_bits ({ n; _ } : pub) = String.length n * 8
  let priv_bits ({ n; _ } : priv) = String.length n * 8
  let priv_of_primes ~e ~p ~q = no_rsa
  let priv_of_exp ?g ?attempts ~e ~d ~n () = no_rsa
  let pub_of_priv ({ e; n; _ } : priv) : pub = { e; n }

  type 'a or_digest = [ `Message of 'a | `Digest of string ]
  type mask = [ `No | `Yes | `Yes_with of Mirage_crypto_rng.g ]

  let encrypt ~key _ = unsupported "RSA encryption"
  let decrypt ?crt_hardening ?mask ~key _ = unsupported "RSA decryption"
  let generate ?g ?e ~bits () = unsupported "RSA key generation"

  module PKCS1 = struct
    let encrypt ?g ~key _ = unsupported "RSA PKCS1 encryption"
    let decrypt ?crt_hardening ?mask ~key _ = unsupported "RSA PKCS1 decryption"
    let sig_encode ?crt_hardening ?mask ~key _ = unsupported "RSA PKCS1 signing"
    let sig_decode ~key _ = unsupported "RSA PKCS1 signature decoding"
    let min_key _ = unsupported "RSA PKCS1 key sizes"
    let sign ?crt_hardening ?mask ~hash ~key _ = unsupported "RSA PKCS1 signing"
    let verify ~hashp ~key ~signature _ = unsupported "RSA PKCS1 verification"
  end

  module OAEP (H : Digestif.S) = struct
    let encrypt ?g ?label ~key _ = unsupported "RSA OAEP encryption"
    let decrypt ?crt_hardening ?mask ?label ~key _ = unsupported "RSA OAEP decryption"
  end

  module PSS (H : Digestif.S) = struct
    let sign ?g ?crt_hardening ?mask ?slen ~key _ = unsupported "RSA PSS signing"
    let verify ?slen ~key ~signature _ = unsupported "RSA PSS verification"
  end
end

module Dh = struct
  exception Invalid_key

  type group = { p : Z.t; gg : Z.t; q : Z.t option }

  let group ~p ~gg ?q () = Ok { p; gg; q }

  type secret = { group : group; x : Z.t }

  let modulus_size g = String.length g.p * 8
  let key_of_secret g ~s = unsupported "finite-field Diffie-Hellman"
  let gen_key ?g ?bits _ = unsupported "finite-field Diffie-Hellman"
  let shared _ _ = unsupported "finite-field Diffie-Hellman"
  let gen_group ?g ~bits () = unsupported "finite-field Diffie-Hellman group generation"

  module Group = struct
    (* The groups are named so that tls compiles; their primes are not present. *)
    let none = { p = ""; gg = "\002"; q = None }
    let oakley_1 = none
    let oakley_2 = none
    let oakley_5 = none
    let oakley_14 = none
    let oakley_15 = none
    let oakley_16 = none
    let oakley_17 = none
    let oakley_18 = none
    let rfc_5114_1 = none
    let rfc_5114_2 = none
    let rfc_5114_3 = none
    let ffdhe2048 = none
    let ffdhe3072 = none
    let ffdhe4096 = none
    let ffdhe6144 = none
    let ffdhe8192 = none
  end
end

module Z_extra = struct
  let of_octets_be ?bits s =
    match bits with
    | None -> s
    | Some b ->
        let bytes = (b + 7) / 8 in
        if bytes >= String.length s then s else String.sub s 0 bytes

  let strip s =
    let n = String.length s in
    let i = ref 0 in
    while !i < n && s.[!i] = '\000' do
      incr i
    done;
    String.sub s !i (n - !i)

  let to_octets_be ?size z =
    let z = strip z in
    match size with
    | None -> z
    | Some n ->
        let l = String.length z in
        if l >= n then String.sub z (l - n) n else String.make (n - l) '\000' ^ z

  let into_octets_be z buf =
    let s = to_octets_be ~size:(Bytes.length buf) z in
    Bytes.blit_string s 0 buf 0 (Bytes.length buf)
end
