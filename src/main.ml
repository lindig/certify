module C = Cmdliner
module Rsa = Mirage_crypto_pk.Rsa
module Result = Stdlib.Result

let to_error e = Result.error (Printexc.to_string e)
let ( >>= ) = Result.bind

let _read_pem src =
  try
    let stat = Unix.stat src in
    let buf = Bytes.create stat.Unix.st_size in
    let fd = Unix.openfile src [ Unix.O_RDONLY ] 0 in
    let _read_b = Unix.read fd buf 0 stat.Unix.st_size in
    let () = Unix.close fd in
    Ok (Cstruct.of_bytes buf)
  with e -> to_error e

let _write_pem dest pem =
  try
    let fd = Unix.openfile dest [ Unix.O_WRONLY; Unix.O_CREAT ] 0o600 in
    let _written_bytes =
      Unix.single_write fd (Cstruct.to_bytes pem) 0 (Cstruct.len pem)
    in
    let () = Unix.close fd in
    Ok ()
  with e -> to_error e

let make_dates days =
  let seconds = days * 24 * 60 * 60 in
  let start = Ptime_clock.now () in
  match Ptime.(add_span start @@ Span.of_int_s seconds) with
  | Some expire -> Some (start, expire)
  | None -> None

let _defer f = Fun.protect ~finally:f

let extensions subject_pubkey auth_pubkey names entity =
  let open X509 in
  let extensions =
    let auth = (Some (Public_key.id auth_pubkey), General_name.empty, None) in
    Extension.(
      add Subject_key_id
        (false, Public_key.id subject_pubkey)
        (singleton Authority_key_id (false, auth)))
  in
  let extensions =
    match names with
    | [] -> extensions
    | _ ->
        Extension.(
          add Subject_alt_name
            (false, General_name.(singleton DNS names))
            extensions)
  in

  let leaf_extensions =
    Extension.(
      add Key_usage
        (true, [ `Digital_signature; `Key_encipherment ])
        (add Basic_constraints (true, (false, None)) extensions))
  in
  match entity with
  | `CA ->
      let ku =
        [ `Key_cert_sign; `CRL_sign; `Digital_signature; `Content_commitment ]
      in
      Extension.(
        add Basic_constraints
          (true, (true, None))
          (add Key_usage (true, ku) extensions))
  | `Client ->
      Extension.(add Ext_key_usage (true, [ `Client_auth ]) leaf_extensions)
  | `Server ->
      Extension.(add Ext_key_usage (true, [ `Server_auth ]) leaf_extensions)

let sign days key pubkey issuer csr names entity =
  match make_dates days with
  | None -> Error (`Msg "Validity period is too long to express - try a shorter one")
  | Some (valid_from, valid_until) ->
    match key, pubkey with
    | `RSA priv, `RSA pub when Nocrypto.Rsa.pub_of_priv priv = pub ->
      let info = X509.Signing_request.info csr in
      let extensions = extensions info.X509.Signing_request.public_key pubkey names entity in
      let cert = X509.Signing_request.sign ~valid_from ~valid_until ~extensions csr key issuer in
      Ok cert
    | _ -> Error (`Msg "public / private keys do not match")


let sign days key pubkey issuer csr names entity =
  match make_dates days with
  | None -> Result.error "days value too large"
  | Some (valid_from, valid_until) -> (
      match (key, pubkey) with
      | `RSA priv, `RSA pub when Rsa.pub_of_priv priv = pub ->
          let info = X509.Signing_request.info csr in
          let extensions =
            extensions info.X509.Signing_request.public_key pubkey names entity
          in
          match X509.Signing_request.sign ~valid_from ~valid_until ~extensions csr
              key issuer with
              | Ok cert -> Ok cert
              | Error msg -> Result.error "something went wrong"
      | _ -> Result.error "public and private key don't match" )

  (*
let _selfsign name length days certfile keyfile =
  let () = Mirage_crypto_rng_unix.initialize () in
  let rsa = Rsa.generate ~bits:length () in
  let privkey = `RSA rsa in
  let pubkey  = `RSA (Rsa.pub_of_priv rsa) in
  let issuer =
    [
      X509.Distinguished_name.(Relative_distinguished_name.singleton (CN name))
    ]
  in
  let csr = X509.Signing_request.create issuer privkey in
  let ent = `Server in
  match
    sign days privkey pubkey issuer csr [] ent
  with
  | Ok cert -> (
      let cert_pem = X509.Certificate.encode_pem cert in
      let key_pem = X509.Private_key.encode_pem privkey in
      match (write_pem certfile cert_pem, write_pem keyfile key_pem) with
      | Ok (), Ok () -> Ok ()
      | Error str, _ | _, Error str -> Error str )
  | Error str -> Error str
*)

let sign name = Printf.printf "Hello, %s!\n" name

module Command = struct
  let help =
    [
      `P "These options are common to all commands."
    ; `S "MORE HELP"
    ; `P "Use `$(mname) $(i,COMMAND) --help' for help on a single command."
    ; `S "BUGS"
    ; `P "Check bug reports at https://github.com/lindig/hello/issues"
    ]

  let name' =
    C.Arg.(
      value & pos 0 string "localhost"
      & info [] ~docv:"NAME" ~doc:"hostname for certifiacte")

  let sign =
    let doc = "Say hello to someone" in
    C.Term.(const sign $ name', info "hello" ~doc ~man:help)
end

let main () = C.Term.(exit @@ eval Command.sign)

let () = if !Sys.interactive then () else main ()
