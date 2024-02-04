## sdp

General-purpose SDP parser.  See [RFC 8866][rfc8866] for the SDP specification.

### Usage

Only `parse/1` is exposed; this expects to receive the full header data with
lines delimited by CRLF, and returns an object representing the session
description.  Since this is a parser **only**, any stipulations imposed by the
RFC regarding server state (such as uniqueness of session IDs) **CANNOT** be
enforced by the parser and **MUST** be validated by the service after a
successful parse.

### Bugs

#### As of 0.1.0

* The parser was implemented based on the ABNF provided in the RFC; this means
  that most of the additional guidance provided has not been implemented.
* The following fields are currently not validated beyond string population:
  * Protocol names
  * Email addresses
  * **All attribute (`a=`) fields**

[rfc8866]: https://datatracker.ietf.org/doc/html/rfc8866
