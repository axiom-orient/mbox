use super::valid_dns_name;
use std::io::{self, Read};
use std::net::TcpStream;
use std::time::{Duration, Instant};

const TLS_CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_TLS_RECORD_PAYLOAD_BYTES: usize = 16 * 1024;
const MAX_TLS_CLIENT_HELLO_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientHelloError {
    Invalid,
    MissingSni,
    DuplicateSni,
    Ech,
    HostMismatch,
    Oversize,
}

#[derive(Debug)]
struct ClientHelloParser {
    expected_host: String,
    wire: Vec<u8>,
    handshake: Vec<u8>,
}

impl ClientHelloParser {
    fn new(expected_host: &str) -> Self {
        Self {
            expected_host: expected_host.to_owned(),
            wire: Vec::with_capacity(4096),
            handshake: Vec::with_capacity(4096),
        }
    }

    fn push_record(&mut self, record: &[u8]) -> Result<bool, ClientHelloError> {
        let payload_length =
            tls_record_payload_length(record.get(..5).ok_or(ClientHelloError::Invalid)?)?;
        let expected_length = 5_usize
            .checked_add(payload_length)
            .ok_or(ClientHelloError::Oversize)?;
        if record.len() != expected_length {
            return Err(ClientHelloError::Invalid);
        }
        let wire_length = self
            .wire
            .len()
            .checked_add(record.len())
            .ok_or(ClientHelloError::Oversize)?;
        if wire_length > MAX_TLS_CLIENT_HELLO_BYTES {
            return Err(ClientHelloError::Oversize);
        }
        self.wire.extend_from_slice(record);
        self.handshake.extend_from_slice(&record[5..]);
        if self.handshake.len() > MAX_TLS_CLIENT_HELLO_BYTES {
            return Err(ClientHelloError::Oversize);
        }
        if self.handshake.len() < 4 {
            return Ok(false);
        }
        if self.handshake[0] != 1 {
            return Err(ClientHelloError::Invalid);
        }
        let message_length = (usize::from(self.handshake[1]) << 16)
            | (usize::from(self.handshake[2]) << 8)
            | usize::from(self.handshake[3]);
        let message_end = 4_usize
            .checked_add(message_length)
            .ok_or(ClientHelloError::Oversize)?;
        if message_end > MAX_TLS_CLIENT_HELLO_BYTES {
            return Err(ClientHelloError::Oversize);
        }
        if self.handshake.len() < message_end {
            return Ok(false);
        }
        validate_client_hello(&self.handshake[..message_end], &self.expected_host)?;
        Ok(true)
    }

    fn into_wire(self) -> Vec<u8> {
        self.wire
    }
}

pub(super) fn read_client_hello(
    client: &mut TcpStream,
    expected_host: &str,
) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + TLS_CLIENT_HELLO_TIMEOUT;
    let mut parser = ClientHelloParser::new(expected_host);
    loop {
        let mut header = [0_u8; 5];
        read_exact_until(client, &mut header, deadline)?;
        let payload_length = tls_record_payload_length(&header).map_err(client_hello_error)?;
        let record_length = 5_usize
            .checked_add(payload_length)
            .ok_or_else(|| client_hello_error(ClientHelloError::Oversize))?;
        if parser
            .wire
            .len()
            .checked_add(record_length)
            .is_none_or(|length| length > MAX_TLS_CLIENT_HELLO_BYTES)
        {
            return Err(client_hello_error(ClientHelloError::Oversize));
        }
        let mut record = Vec::with_capacity(record_length);
        record.extend_from_slice(&header);
        let mut payload = vec![0_u8; payload_length];
        read_exact_until(client, &mut payload, deadline)?;
        record.extend_from_slice(&payload);
        if parser.push_record(&record).map_err(client_hello_error)? {
            return Ok(parser.into_wire());
        }
    }
}

fn read_exact_until(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    let mut offset = 0;
    while offset < buffer.len() {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "TLS ClientHello deadline exceeded",
            ));
        }
        match stream.read(&mut buffer[offset..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "TLS ClientHello ended before the first message",
                ));
            }
            Ok(size) => offset += size,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn tls_record_payload_length(header: &[u8]) -> Result<usize, ClientHelloError> {
    if header.len() != 5 || header[0] != 22 || header[1] != 3 || !(1..=4).contains(&header[2]) {
        return Err(ClientHelloError::Invalid);
    }
    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if length > MAX_TLS_RECORD_PAYLOAD_BYTES {
        return Err(ClientHelloError::Oversize);
    }
    Ok(length)
}

fn validate_client_hello(message: &[u8], expected_host: &str) -> Result<(), ClientHelloError> {
    if message.len() < 4 || message[0] != 1 {
        return Err(ClientHelloError::Invalid);
    }
    let message_length =
        (usize::from(message[1]) << 16) | (usize::from(message[2]) << 8) | usize::from(message[3]);
    if message_length.checked_add(4) != Some(message.len()) {
        return Err(ClientHelloError::Invalid);
    }
    let body = &message[4..];
    let mut offset = 0;
    take_bytes(body, &mut offset, 2)?;
    take_bytes(body, &mut offset, 32)?;
    let session_id_length = usize::from(read_u8(body, &mut offset)?);
    take_bytes(body, &mut offset, session_id_length)?;
    let cipher_suites_length = usize::from(read_u16(body, &mut offset)?);
    if cipher_suites_length == 0 || cipher_suites_length % 2 != 0 {
        return Err(ClientHelloError::Invalid);
    }
    take_bytes(body, &mut offset, cipher_suites_length)?;
    let compression_methods_length = usize::from(read_u8(body, &mut offset)?);
    if compression_methods_length == 0 {
        return Err(ClientHelloError::Invalid);
    }
    take_bytes(body, &mut offset, compression_methods_length)?;
    let extensions_length = usize::from(read_u16(body, &mut offset)?);
    let extensions_end = offset
        .checked_add(extensions_length)
        .ok_or(ClientHelloError::Invalid)?;
    if extensions_end != body.len() {
        return Err(ClientHelloError::Invalid);
    }

    let mut saw_sni = false;
    while offset < extensions_end {
        let extension_type = read_u16(body, &mut offset)?;
        let extension_length = usize::from(read_u16(body, &mut offset)?);
        let extension = take_bytes(body, &mut offset, extension_length)?;
        if extension_type == 0xfe0d {
            return Err(ClientHelloError::Ech);
        }
        if extension_type == 0 {
            if saw_sni {
                return Err(ClientHelloError::DuplicateSni);
            }
            saw_sni = true;
            validate_sni_extension(extension, expected_host)?;
        }
    }
    if !saw_sni {
        return Err(ClientHelloError::MissingSni);
    }
    Ok(())
}

fn validate_sni_extension(extension: &[u8], expected_host: &str) -> Result<(), ClientHelloError> {
    let mut offset = 0;
    let list_length = usize::from(read_u16(extension, &mut offset)?);
    let list_end = offset
        .checked_add(list_length)
        .ok_or(ClientHelloError::Invalid)?;
    if list_end != extension.len() {
        return Err(ClientHelloError::Invalid);
    }
    let mut names = 0;
    while offset < list_end {
        let name_type = read_u8(extension, &mut offset)?;
        let name_length = usize::from(read_u16(extension, &mut offset)?);
        let name = take_bytes(extension, &mut offset, name_length)?;
        if name_type != 0 || name.is_empty() || names != 0 {
            return Err(if names != 0 {
                ClientHelloError::DuplicateSni
            } else {
                ClientHelloError::Invalid
            });
        }
        let name = std::str::from_utf8(name).map_err(|_| ClientHelloError::Invalid)?;
        if !valid_dns_name(name) {
            return Err(ClientHelloError::Invalid);
        }
        if !name.eq_ignore_ascii_case(expected_host) {
            return Err(ClientHelloError::HostMismatch);
        }
        names += 1;
    }
    if names != 1 {
        return Err(ClientHelloError::MissingSni);
    }
    Ok(())
}

fn take_bytes<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    length: usize,
) -> Result<&'a [u8], ClientHelloError> {
    let end = offset
        .checked_add(length)
        .ok_or(ClientHelloError::Invalid)?;
    let result = bytes.get(*offset..end).ok_or(ClientHelloError::Invalid)?;
    *offset = end;
    Ok(result)
}

fn read_u8(bytes: &[u8], offset: &mut usize) -> Result<u8, ClientHelloError> {
    let value = *take_bytes(bytes, offset, 1)?
        .first()
        .ok_or(ClientHelloError::Invalid)?;
    Ok(value)
}

fn read_u16(bytes: &[u8], offset: &mut usize) -> Result<u16, ClientHelloError> {
    let value = take_bytes(bytes, offset, 2)?;
    Ok(u16::from_be_bytes([value[0], value[1]]))
}

fn client_hello_error(error: ClientHelloError) -> io::Error {
    let kind = match error {
        ClientHelloError::Oversize => io::ErrorKind::InvalidData,
        ClientHelloError::Invalid
        | ClientHelloError::MissingSni
        | ClientHelloError::DuplicateSni
        | ClientHelloError::Ech
        | ClientHelloError::HostMismatch => io::ErrorKind::PermissionDenied,
    };
    io::Error::new(
        kind,
        "TLS ClientHello is not authorized for the CONNECT domain",
    )
}

#[cfg(test)]
mod tests {
    use super::{ClientHelloError, ClientHelloParser};

    #[test]
    fn client_hello_parser_requires_exact_sni_and_handles_record_fragmentation() {
        let message = client_hello_message(&sni_extension("raw.githubusercontent.com"));
        let split = 7;
        let first = tls_record(&message[..split]);
        let second = tls_record(&message[split..]);
        let mut parser = ClientHelloParser::new("raw.githubusercontent.com");
        assert!(!parser.push_record(&first).unwrap());
        assert!(parser.push_record(&second).unwrap());
        let mut expected = first;
        expected.extend_from_slice(&second);
        assert_eq!(parser.into_wire(), expected);

        let mut mismatch = ClientHelloParser::new("raw.githubusercontent.com");
        assert_eq!(
            mismatch.push_record(&tls_record(&client_hello_message(&sni_extension(
                "avatars.githubusercontent.com"
            )))),
            Err(ClientHelloError::HostMismatch)
        );
    }

    #[test]
    fn client_hello_parser_rejects_absent_duplicate_malformed_and_ech_sni() {
        let cases = [
            (client_hello_message(&[]), ClientHelloError::MissingSni),
            (
                client_hello_message(&{
                    let extension = sni_extension("example.com");
                    [extension.clone(), extension].concat()
                }),
                ClientHelloError::DuplicateSni,
            ),
            (
                client_hello_message(&sni_extension_with_hosts(&["example.com", "example.com"])),
                ClientHelloError::DuplicateSni,
            ),
            (
                client_hello_message(&{
                    let mut extension = sni_extension("example.com");
                    extension[4] = 0;
                    extension[5] = 0;
                    extension
                }),
                ClientHelloError::Invalid,
            ),
            (
                client_hello_message(&extension(0xfe0d, &[])),
                ClientHelloError::Ech,
            ),
        ];
        for (message, expected) in cases {
            let mut parser = ClientHelloParser::new("example.com");
            assert_eq!(
                parser.push_record(&tls_record(&message)),
                Err(expected),
                "unexpected ClientHello result for {expected:?}"
            );
        }
    }

    #[test]
    fn client_hello_parser_rejects_record_and_message_bounds() {
        let mut parser = ClientHelloParser::new("example.com");
        let mut plaintext = tls_record(&[0]);
        plaintext[0] = 23;
        assert_eq!(
            parser.push_record(&plaintext),
            Err(ClientHelloError::Invalid)
        );
        assert_eq!(
            parser.push_record(&[22, 3, 3, 0x40, 0x01]),
            Err(ClientHelloError::Oversize)
        );

        let mut oversized = vec![1, 0xff, 0xff, 0xff];
        oversized.resize(4 + 64 * 1024, 0);
        let record = tls_record(&oversized[..16 * 1024]);
        assert_eq!(parser.push_record(&record), Err(ClientHelloError::Oversize));
    }

    fn extension(kind: u16, data: &[u8]) -> Vec<u8> {
        let mut value = Vec::with_capacity(4 + data.len());
        value.extend_from_slice(&kind.to_be_bytes());
        value.extend_from_slice(&(u16::try_from(data.len()).unwrap()).to_be_bytes());
        value.extend_from_slice(data);
        value
    }

    fn sni_extension(host: &str) -> Vec<u8> {
        sni_extension_with_hosts(&[host])
    }

    fn sni_extension_with_hosts(hosts: &[&str]) -> Vec<u8> {
        let list_length = hosts.iter().map(|host| 3 + host.len()).sum::<usize>();
        let mut data = Vec::with_capacity(2 + list_length);
        data.extend_from_slice(&(u16::try_from(list_length).unwrap()).to_be_bytes());
        for host in hosts {
            let host = host.as_bytes();
            data.push(0);
            data.extend_from_slice(&(u16::try_from(host.len()).unwrap()).to_be_bytes());
            data.extend_from_slice(host);
        }
        extension(0, &data)
    }

    fn client_hello_message(extensions: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[3, 3]);
        body.extend_from_slice(&[0; 32]);
        body.push(0);
        body.extend_from_slice(&[0, 2, 0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&(u16::try_from(extensions.len()).unwrap()).to_be_bytes());
        body.extend_from_slice(extensions);

        let mut message = Vec::with_capacity(4 + body.len());
        message.push(1);
        let length = u32::try_from(body.len()).unwrap();
        message.extend_from_slice(&[
            u8::try_from((length >> 16) & 0xff).unwrap(),
            u8::try_from((length >> 8) & 0xff).unwrap(),
            u8::try_from(length & 0xff).unwrap(),
        ]);
        message.extend_from_slice(&body);
        message
    }

    fn tls_record(payload: &[u8]) -> Vec<u8> {
        let length = u16::try_from(payload.len()).unwrap();
        let mut record = vec![22, 3, 3];
        record.extend_from_slice(&length.to_be_bytes());
        record.extend_from_slice(payload);
        record
    }
}
