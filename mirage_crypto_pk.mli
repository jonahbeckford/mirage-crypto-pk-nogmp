(** A replacement for [mirage-crypto-pk] 2.0.2 that has no arithmetic.

    The module names, the types and the signatures are those of [mirage-crypto-pk] 2.0.2, as far
    as the [tls] and [x509] packages use them, with one change: the big numbers [Z.t] are strings
    of big-endian bytes here, and no operation computes with them. A key of RSA cannot be made
    ({!Rsa.pub} and {!Rsa.priv} give an error), and every other operation of RSA and of
    finite-field Diffie-Hellman raises [Failure "unsupported: ..."].

    A TLS server whose certificate is ECDSA or Ed25519, and whose key exchange is ECDHE or TLS
    1.3, uses nothing of this module. *)

module Z : sig
  type t = string
  (** A non-negative integer as the bytes of its big-endian form. *)
end

module Rsa : sig
  exception Insufficient_key

  type pub = private { e : Z.t; n : Z.t }

  val pub : e:Z.t -> n:Z.t -> (pub, [> `Msg of string ]) result

  type priv = private {
    e : Z.t;
    d : Z.t;
    n : Z.t;
    p : Z.t;
    q : Z.t;
    dp : Z.t;
    dq : Z.t;
    q' : Z.t;
  }

  val priv :
    e:Z.t ->
    d:Z.t ->
    n:Z.t ->
    p:Z.t ->
    q:Z.t ->
    dp:Z.t ->
    dq:Z.t ->
    q':Z.t ->
    (priv, [> `Msg of string ]) result

  val pub_bits : pub -> int
  val priv_bits : priv -> int
  val priv_of_primes : e:Z.t -> p:Z.t -> q:Z.t -> (priv, [> `Msg of string ]) result

  val priv_of_exp :
    ?g:Mirage_crypto_rng.g ->
    ?attempts:int ->
    e:Z.t ->
    d:Z.t ->
    n:Z.t ->
    unit ->
    (priv, [> `Msg of string ]) result

  val pub_of_priv : priv -> pub

  type 'a or_digest = [ `Message of 'a | `Digest of string ]
  type mask = [ `No | `Yes | `Yes_with of Mirage_crypto_rng.g ]

  val encrypt : key:pub -> string -> string
  val decrypt : ?crt_hardening:bool -> ?mask:mask -> key:priv -> string -> string
  val generate : ?g:Mirage_crypto_rng.g -> ?e:Z.t -> bits:int -> unit -> priv

  module PKCS1 : sig
    val encrypt : ?g:Mirage_crypto_rng.g -> key:pub -> string -> string

    val decrypt :
      ?crt_hardening:bool -> ?mask:mask -> key:priv -> string -> string option

    val sig_encode : ?crt_hardening:bool -> ?mask:mask -> key:priv -> string -> string
    val sig_decode : key:pub -> string -> string option

    val min_key :
      [< Digestif.hash' > `MD5 `SHA1 `SHA224 `SHA256 `SHA384 `SHA512 ] -> int

    val sign :
      ?crt_hardening:bool ->
      ?mask:mask ->
      hash:[< Digestif.hash' > `MD5 `SHA1 `SHA224 `SHA256 `SHA384 `SHA512 ] ->
      key:priv ->
      string or_digest ->
      string

    val verify :
      hashp:([< Digestif.hash' > `MD5 `SHA1 `SHA224 `SHA256 `SHA384 `SHA512 ] -> bool) ->
      key:pub ->
      signature:string ->
      string or_digest ->
      bool
  end

  module OAEP (H : Digestif.S) : sig
    val encrypt :
      ?g:Mirage_crypto_rng.g -> ?label:string -> key:pub -> string -> string

    val decrypt :
      ?crt_hardening:bool ->
      ?mask:mask ->
      ?label:string ->
      key:priv ->
      string ->
      string option
  end

  module PSS (H : Digestif.S) : sig
    val sign :
      ?g:Mirage_crypto_rng.g ->
      ?crt_hardening:bool ->
      ?mask:mask ->
      ?slen:int ->
      key:priv ->
      string or_digest ->
      string

    val verify :
      ?slen:int -> key:pub -> signature:string -> string or_digest -> bool
  end
end

module Dh : sig
  exception Invalid_key

  type group = private { p : Z.t; gg : Z.t; q : Z.t option }

  val group : p:Z.t -> gg:Z.t -> ?q:Z.t -> unit -> (group, [> `Msg of string ]) result

  type secret = private { group : group; x : Z.t }

  val modulus_size : group -> int
  val key_of_secret : group -> s:string -> secret * string
  val gen_key : ?g:Mirage_crypto_rng.g -> ?bits:int -> group -> secret * string
  val shared : secret -> string -> string option
  val gen_group : ?g:Mirage_crypto_rng.g -> bits:int -> unit -> group

  module Group : sig
    val oakley_1 : group
    val oakley_2 : group
    val oakley_5 : group
    val oakley_14 : group
    val oakley_15 : group
    val oakley_16 : group
    val oakley_17 : group
    val oakley_18 : group
    val rfc_5114_1 : group
    val rfc_5114_2 : group
    val rfc_5114_3 : group
    val ffdhe2048 : group
    val ffdhe3072 : group
    val ffdhe4096 : group
    val ffdhe6144 : group
    val ffdhe8192 : group
  end
end

module Z_extra : sig
  val of_octets_be : ?bits:int -> string -> Z.t
  val to_octets_be : ?size:int -> Z.t -> string
  val into_octets_be : Z.t -> bytes -> unit
end
