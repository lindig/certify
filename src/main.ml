module C = Cmdliner
module Rsa = Mirage_crypto_pk.Rsa
open Rresult (* introduces >>= >>| and R *)

(** initialize the random number generator at program startup when this
module is loaded. *)
let () = Mirage_crypto_rng_unix.initialize ()

let defer f = Fun.protect ~finally:f

let write fd bytes offset length =
  let written = Unix.write fd bytes offset length in
  if written = length then R.ok ()
  else R.error_msgf "Failed to write %d bytes" length

let write_substring fd string offset length =
  let written = Unix.write_substring fd string offset length in
  if written = length then R.ok ()
  else R.error_msgf "Failed to write %d bytes" length

let read_pem path =
  let ic = open_in path in
  defer (fun () -> close_in ic) @@ fun () ->
  really_input_string ic (in_channel_length ic)

(** [write_cert] writes a PEM file to [path]. It attempts to do that
  atomically by writing to a temporary file in the same directory first and
  renaming the file at the end *)
let write_certs path key cert =
  let delimit = "\n" in
  let temp_dir = Filename.dirname path in
  let tmp = Filename.temp_file ~temp_dir "certify-" ".tmp" in
  try
    let fd = Unix.openfile tmp [ Unix.O_WRONLY ] 0o600 in
    defer (fun () -> Unix.close fd) @@ fun () ->
    write fd (Cstruct.to_bytes key) 0 (Cstruct.len key) >>= fun () ->
    write_substring fd delimit 0 (String.length delimit) >>= fun () ->
    write fd (Cstruct.to_bytes cert) 0 (Cstruct.len cert) >>= fun () ->
    Unix.rename tmp path;
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

let sign days key pubkey issuer req alt_names =
  expire_in days >>= fun (valid_from, valid_until) ->
  match (key, pubkey) with
  | `RSA priv, `RSA pub when Rsa.pub_of_priv priv = pub ->
      let extensions = add_dns_names X509.Extension.empty alt_names in
      X509.Signing_request.sign ~valid_from ~valid_until ~extensions req key
        issuer
      |> R.reword_error (fun _ -> Printf.sprintf "signing failed" |> R.msg)
  | _ -> R.error_msgf "public/private keys don't match (%s)" __LOC__

let selfsign rsa_key_file name alt_names length days certfile =
  let rsa =
    match rsa_key_file with
    | Some path -> (
        read_pem path |> Cstruct.of_string |> X509.Private_key.decode_pem
        |> R.get_ok
        |> function
        | `RSA x -> x )
    | None -> Rsa.generate ~bits:length ()
  in
  let privkey = `RSA rsa in
  let pubkey = `RSA (Rsa.pub_of_priv rsa) in
  let issuer =
    [
      X509.Distinguished_name.(Relative_distinguished_name.singleton (CN name))
    ]
  in
  let req = X509.Signing_request.create issuer privkey in
  sign days privkey pubkey issuer req alt_names >>= fun cert ->
  let cert_pem = X509.Certificate.encode_pem cert in
  let key_pem = X509.Private_key.encode_pem privkey in
  write_certs certfile key_pem cert_pem

let hostnames () =
  let hostname = Unix.gethostname () in
  Unix.getaddrinfo hostname "" [ Unix.AI_CANONNAME ]
  |> List.filter_map (fun addrinfo ->
         match addrinfo.Unix.ai_canonname with "" -> None | name -> Some name)

let host name alt_names gethostnames pemfile _rsa_key =
  let expire_days = 3650 in
  let length = 2048 in
  let alt_names =
    alt_names @ match gethostnames with false -> [] | true -> hostnames ()
  in
  selfsign _rsa_key name alt_names length expire_days pemfile
  |> R.failwith_error_msg

module CLI = struct
  let help =
    [
      `P "These options are common to all commands."
    ; `S "MORE HELP"
    ; `P "Use `$(mname) $(i,COMMAND) --help' for help on a single command."
    ; `S "BUGS"
    ; `P "Check bug reports at https://github.com/lindig/certify/issues"
    ]

  let pemfile =
    C.Arg.(
      value & opt string "certify.pem"
      & info [ "o"; "pem"; "out" ] ~docv:"FILE.PEM" ~doc:"Target for PEM cert.")

  let gethostnames =
    C.Arg.(
      value & opt bool false
      & info [ "dns" ] ~docv:"DNS"
          ~doc:
            {|Use gethostname() results for alternative names. This
          queries localhost for names hostname.|})

  let hostname =
    C.Arg.(
      value & pos 0 string "localhost"
      & info [] ~docv:"NAME" ~doc:"hostname for certificate")

  let alt_names =
    C.Arg.(
      value & opt_all string []
      & info [ "a"; "alt" ] ~docv:"ALT" ~doc:"Add alternative hostname")

  let rsa_key =
    C.Arg.(
      value
      & opt (some file) None
      & info [ "rsa" ] ~docv:"rsa.pem" ~doc:"Use this private RSA key file")

  let certify =
    let doc = "issue a self-signed certificate for a host" in
    C.Term.
      ( const host $ hostname $ alt_names $ gethostnames $ pemfile $ rsa_key
      , info "certify" ~doc ~man:help )

  let main () = C.Term.(exit @@ eval certify)
end

let () = CLI.main ()
