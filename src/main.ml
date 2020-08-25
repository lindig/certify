module C = Cmdliner
module Rsa = Mirage_crypto_pk.Rsa
open Rresult

let defer f = Fun.protect ~finally:f

let write_certs dest key cert =
  let delimit = "\n" in
  try
    let fd = Unix.openfile dest [ Unix.O_WRONLY; Unix.O_CREAT ] 0o600 in
    defer (fun () -> Unix.close fd) @@ fun () ->
    ignore @@ Unix.single_write fd (Cstruct.to_bytes key) 0 (Cstruct.len key);
    ignore @@ Unix.single_write_substring fd delimit 0 (String.length delimit);
    ignore @@ Unix.single_write fd (Cstruct.to_bytes cert) 0 (Cstruct.len cert);
    R.ok ()
  with e -> R.error_msg (Printexc.to_string e)

let expire_in days =
  let seconds = days * 24 * 60 * 60 in
  let start = Ptime_clock.now () in
  match Ptime.(add_span start @@ Span.of_int_s seconds) with
  | Some expire -> R.ok (start, expire)
  | None -> R.error_msgf "can't represent %d as time span" days

let add_dns_names extension = function
  | [] -> extension
  | names ->
      X509.Extension.(
        add Subject_alt_name
          (false, X509.General_name.(singleton DNS names))
          extension)

let sign days key pubkey issuer req alt_names _entity =
  expire_in days >>= fun (valid_from, valid_until) ->
  match (key, pubkey) with
  | `RSA priv, `RSA pub when Rsa.pub_of_priv priv = pub ->
      let _info = X509.Signing_request.info req in
      let extensions = add_dns_names X509.Extension.empty alt_names in
      X509.Signing_request.sign ~valid_from ~valid_until ~extensions req key
        issuer
      |> R.reword_error (fun _ -> `Msg "something went wrong")
  | _ -> R.error_msg "public/private keys don't match"

let selfsign name alt_names length days certfile =
  let rsa = Rsa.generate ~bits:length () in
  let privkey = `RSA rsa in
  let pubkey = `RSA (Rsa.pub_of_priv rsa) in
  let issuer =
    [
      X509.Distinguished_name.(Relative_distinguished_name.singleton (CN name))
    ]
  in
  let req = X509.Signing_request.create issuer privkey in
  let ent = `Server in
  sign days privkey pubkey issuer req alt_names ent >>= fun cert ->
  let cert_pem = X509.Certificate.encode_pem cert in
  let key_pem = X509.Private_key.encode_pem privkey in
  write_certs certfile key_pem cert_pem

let sign name alt_names =
  let () = Mirage_crypto_rng_unix.initialize () in
  let expire_days = 3650 in
  let certfile = Printf.sprintf "%s.pem" name in
  let length = 2048 in
  selfsign name alt_names length expire_days certfile |> R.failwith_error_msg

module Command = struct
  let help =
    [
      `P "These options are common to all commands."
    ; `S "MORE HELP"
    ; `P "Use `$(mname) $(i,COMMAND) --help' for help on a single command."
    ; `S "BUGS"
    ; `P "Check bug reports at https://github.com/lindig/hello/issues"
    ]

  let host =
    C.Arg.(
      value & pos 0 string "localhost"
      & info [] ~docv:"NAME" ~doc:"hostname for certificate")

 let alt_names =
    C.Arg.(
      value & opt_all string []
      & info ["d"; "dns"] ~docv:"DNS" ~doc:"Alternative hostname")
  
  let sign =
    let doc = "Create a self-signed cert for a host" in
    C.Term.(const sign $ host $ alt_names, info "certify" ~doc ~man:help)
end

let main () = C.Term.(exit @@ eval Command.sign)

let () = if !Sys.interactive then () else main ()
