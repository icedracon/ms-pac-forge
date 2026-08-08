# ms-pac-forge

MS-PAC (Privilege Attribute Certificate) marshaling and Golden/Silver Kerberos
ticket forgery in pure Rust. Builds a KERB_VALIDATION_INFO buffer whose NDR
layout was validated byte-for-byte against a live Windows Server 2025 KDC PAC,
signs it (SERVER_CHECKSUM + KDC_CHECKSUM, AES-HMAC-SHA1-96 or RC4 HMAC-MD5),
wraps it in an EncTicketPart, and seals it under the krbtgt (golden) or
service-account (silver) key. KB5020805 PAC-signature enforcement is
respected (both signatures emitted; PAC_ATTRIBUTES + PAC_REQUESTOR present).

**STATUS: pre-alpha, extracted from adhammer 1.3.1.** Golden and Silver
builders only in v0.1; Diamond/Sapphire and the full PAC dissector deferred.
No live KDC transport here — this crate produces the raw
`Ticket`/session-key/PAC bytes; wire them to your own AS/TGS layer or MIT
ccache serializer.

MIT licensed.
