use super::bpf;
use byteorder::NetworkEndian;
use byteorder::ReadBytesExt;
use hpack::Decoder;
use std::collections::HashMap;
use std::fmt::Display;
use std::io::Cursor;
use std::io::Error;
use std::result::Result;

#[derive(Debug)]
enum ParseError {
    IncompleteFrame,
    ProtocolError(String),
    TooSmall,
    FrameSizeError,
    UnknownFrameType(u8),
    InvalidFrame(String),
    IoError(std::io::Error),
}

#[derive(Debug, PartialEq, Clone, Copy)]
enum FrameType {
    Data,
    Headers,
    Priority,
    RstStream,
    Settings,
    PushPromise,
    Ping,
    GoAway,
    WindowUpdate,
    Continuation,
}

impl FrameType {
    fn try_parse(d: u8) -> Result<FrameType, ParseError> {
        match d {
            0x0 => Ok(FrameType::Data),
            0x1 => Ok(FrameType::Headers),
            0x2 => Ok(FrameType::Priority),
            0x3 => Ok(FrameType::RstStream),
            0x4 => Ok(FrameType::Settings),
            0x5 => Ok(FrameType::PushPromise),
            0x6 => Ok(FrameType::Ping),
            0x7 => Ok(FrameType::GoAway),
            0x8 => Ok(FrameType::WindowUpdate),
            0x9 => Ok(FrameType::Continuation),
            _ => Err(ParseError::UnknownFrameType(d)),
        }
    }
}

impl Display for FrameType {
    fn fmt(self: &Self, formatter: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let mut val = format!("{:?}", self);
        val.make_ascii_uppercase();
        write!(formatter, "{}", val)
    }
}

fn flagged(f: u8, flags: u8) -> bool {
    f & flags != 0
}

#[derive(Copy, Clone, Debug)]
struct FrameHeader {
    // Not part of the HTTP/2 frame header: this indicates whether this was a HTTP/2 frame sent by the client.
    client: bool,
    // Size of the HTTP/2 frame payload.
    len: usize,
    frame_type: FrameType,
    raw_flags: u8,
    stream_id: u32,
}

// A RawFrame is the frame header with a payload. Typed frames parse the contents of the payload and add semantic
// meaning to the bits set in header.raw_flags.
#[derive(Debug)]
struct RawFrame {
    header: FrameHeader,
    payload: Vec<u8>,
}

// Meaning of flags set on a DATA frame.
#[derive(Debug)]
enum DataFlag {
    EndStream = 0x1,
    Padded = 0x8,
}

// Header values specific to the DATA frame.
#[derive(Debug)]
struct DataHeader {
    end_stream: bool,
    padded: bool,
}

// Meaning of flags set on a HEADERS frame.
#[derive(Debug)]
enum HeadersFlag {
    EndStream = 0x1,
    EndHeaders = 0x4,
    Padded = 0x8,
    Priority = 0x20,
}

// Header values specific to a HEADERS frame.
#[derive(Debug)]
struct HeadersHeader {
    end_stream: bool,
    end_headers: bool,
    padded: bool,
    priority: bool,
}

// Meaning of flags set on a CONTINUATION frame.
#[derive(Debug)]
enum ContinuationFlag {
    EndHeaders = 0x4,
}

// Header values specific to a CONTINUATION frame.
#[derive(Debug)]
struct ContinuationHeader {
    end_headers: bool,
}

// Meaning of flags set on a SETTINGS frame.
#[derive(Debug)]
enum SettingFlags {
    Ack = 0x1,
}

// Header values specific to a SETTINGS frame.
#[derive(Debug)]
struct SettingsHeader {
    ack: bool,
}

// Meaning of identifiers set in a SETTINGS payload.
#[derive(Debug)]
enum StreamSetting {
    TableSize = 0x1,
    EnablePush = 0x2,
    MaxConcurrentStreams = 0x3,
    InitialWindowSize = 0x4,
    MaxFrameSize = 0x5,
    MaxHeaderListSize = 0x6,
    Unknown = 0x0,
}

// Meaning of flags set on a PRIORITY frame.
#[derive(Debug)]
struct PriorityHeader {
    stream_dependency: u32,
    exclusive: bool,
    weight: u8,
}

#[derive(Debug)]
enum PushPromiseFlags {
    EndHeaders = 0x4,
    Padded = 0x8,
}

#[derive(Debug)]
struct PushPromiseHeaders {
    padded: bool,
    end_headers: bool,
}

#[derive(Debug)]
enum ParsedHeaders {
    Full(Vec<(String, String)>),
    // We use this to denote that we did not have enough information to parse out full header values. HPACK encoding is
    // stateful, so many header fragments will require knowledge of the previous fragments sent on the same stream to make
    // sense. Until we do the work to track stream lifetimes (made complicated by the fact that multiple connections are
    // observed at the same time) we'll improve the handling here. Alternatively, we can parse the HPACK data ourselves
    // and output the partial updates instead of attempting to maintain state.
    Incomplete,
}

impl Display for ParsedHeaders {
    fn fmt(self: &Self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            ParsedHeaders::Full(hs) => {
                for (key, value) in hs {
                    write!(f, "\n{}: {}", key, value)?;
                }
            }
            ParsedHeaders::Incomplete => {
                write!(f, "[incomplete]")?;
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
enum TypedFrame {
    Data(FrameHeader, DataHeader, Vec<u8>),
    Headers(FrameHeader, HeadersHeader, ParsedHeaders),
    Continuation(FrameHeader, ContinuationHeader, ParsedHeaders),
    SettingsFrame(FrameHeader, SettingsHeader, Vec<(StreamSetting, u32)>),
    PriorityFrame(FrameHeader, PriorityHeader),
    WindowUpdate(FrameHeader, u32),
    PushPromise(FrameHeader, PushPromiseHeaders, u32, ParsedHeaders),
    GoAway(FrameHeader, u32, u32, String), // TODO use struct
    Ping(FrameHeader, Vec<u8>),
    RstStream(FrameHeader, u32),
}

// Reads the size of the padding from the provided payload and returns a vec
// of the payload with the padding removed. Returns the original payload if
// padded is false.
fn remove_padding(payload: &[u8], padded: bool) -> Result<Vec<u8>, ParseError> {
    let (start, stop) = if padded {
        let mut c = Cursor::new(&payload);
        let pad_len = c.read_u8()?;

        // This shouldn't happen
        if pad_len as usize > payload.len() {
            return Err(ParseError::ProtocolError(
                "padding exceeds payload".to_string(),
            ));
        }
        (4, payload.len() - pad_len as usize)
    } else {
        (0, payload.len())
    };

    Ok(payload[start..stop].to_vec())
}

// Parses out the hpack encoded headers from a payload. This is used both by HEADERS and CONTINUATION frames.
fn try_parse_header_block(payload: &[u8]) -> Result<ParsedHeaders, ParseError> {
    let mut d = Decoder::new();
    match d.decode(&payload) {
        Ok(decoded) => {
            let mut headers = Vec::new();
            for (key, value) in decoded {
                let key_str = String::from_utf8(key)
                    .map_err(|_| ParseError::InvalidFrame("invalid header key".to_string()))?;
                let value_str = String::from_utf8(value)
                    .map_err(|_| ParseError::InvalidFrame("invalid header value".to_string()))?;

                headers.push((key_str, value_str));
            }
            Ok(ParsedHeaders::Full(headers))
        }
        // TODO we might be silently ignoring real issues, but the decoder doesn't expose enough information
        // for us to tell.
        Err(_) => Ok(ParsedHeaders::Incomplete),
    }
}

impl TypedFrame {
    // DATA payload format:
    //  +---------------+
    //  |Pad Length? (8)|
    //  +---------------+-----------------------------------------------+
    //  |                            Data (*)                         ...
    //  +---------------------------------------------------------------+
    //  |                           Padding (*)                       ...
    //  +---------------------------------------------------------------+
    //
    // If the DataFlag::Padded flag is set, the first 8 bits will be the length
    // of the padding.
    fn try_parse_data(f: &RawFrame) -> Result<Self, ParseError> {
        let padded = flagged(DataFlag::Padded as u8, f.header.raw_flags);
        let end_stream = flagged(DataFlag::EndStream as u8, f.header.raw_flags);
        let data_header = DataHeader { end_stream, padded };
        Ok(TypedFrame::Data(
            f.header,
            data_header,
            remove_padding(&f.payload, padded)?,
        ))
    }

    // HEADERS payload format:
    //  +---------------+
    //  |Pad Length? (8)|
    //  +-+-------------+-----------------------------------------------+
    //  |E|                 Stream Dependency? (31)                     |
    //  +-+-------------+-----------------------------------------------+
    //  |  Weight? (8)  |
    //  +-+-------------+-----------------------------------------------+
    //  |                   Header Block Fragment (*)                 ...
    //  +---------------------------------------------------------------+
    //  |                           Padding (*)                       ...
    //  +---------------------------------------------------------------+
    //
    // Stream Dependency and Weight are only present when the HeadersFlag::Priority flag is set.
    //
    // If the HeadersFlag::Padded flag is set, the first 8 bits will be the length
    // of the padding.
    fn try_parse_headers(f: &RawFrame) -> Result<Self, ParseError> {
        let padded = flagged(HeadersFlag::Padded as u8, f.header.raw_flags);
        let end_stream = flagged(HeadersFlag::EndStream as u8, f.header.raw_flags);
        let end_headers = flagged(HeadersFlag::EndHeaders as u8, f.header.raw_flags);
        let priority = flagged(HeadersFlag::Priority as u8, f.header.raw_flags); // TODO handle this
        let payload = remove_padding(&f.payload, padded)?;

        let header_block = if priority {
            payload[5..].into()
        } else {
            payload
        };

        // TODO parse weight + stream dependency
        Ok(TypedFrame::Headers(
            f.header,
            HeadersHeader {
                padded,
                end_stream,
                end_headers,
                priority,
            },
            try_parse_header_block(&header_block)?,
        ))
    }

    // SETTINGS payload format:
    //  +-------------------------------+
    //  |       Identifier (16)         |
    //  +-------------------------------+-------------------------------+
    //  |                        Value (32)                             |
    //  +---------------------------------------------------------------+
    //
    // The SETTINGS payload contains zero or more identifier-value pairs.
    fn try_parse_settings(f: &RawFrame) -> Result<Self, ParseError> {
        if f.payload.len() % 6 != 0 {
            return Err(ParseError::FrameSizeError);
        }

        let mut settings = Vec::new();
        let mut cursor = Cursor::new(&f.payload);
        while cursor.position() < f.payload.len() as u64 {
            let identifier_val = cursor.read_u16::<NetworkEndian>()?;

            // TODO handle this stuff better, get the derive macro to work
            let identifier = match identifier_val {
                0x1 => StreamSetting::TableSize,
                0x2 => StreamSetting::EnablePush,
                0x3 => StreamSetting::MaxConcurrentStreams,
                0x4 => StreamSetting::InitialWindowSize,
                0x5 => StreamSetting::MaxFrameSize,
                0x6 => StreamSetting::MaxHeaderListSize,
                _ => StreamSetting::Unknown,
            };

            let value = cursor.read_u32::<NetworkEndian>()?;
            settings.push((identifier, value));
        }

        let ack = flagged(SettingFlags::Ack as u8, f.header.raw_flags);
        Ok(TypedFrame::SettingsFrame(
            f.header,
            SettingsHeader { ack },
            settings,
        ))
    }

    // PRIORITY payload format:
    //  +-+-------------------------------------------------------------+
    //  |E|                  Stream Dependency (31)                     |
    //  +-+-------------+-----------------------------------------------+
    //  |   Weight (8)  |
    //  +-+-------------+
    fn try_parse_priority(f: &RawFrame) -> Result<Self, ParseError> {
        if f.payload.len() != 5 {
            return Err(ParseError::FrameSizeError);
        }

        let mut cursor = Cursor::new(&f.payload);
        let dependency_with_flag = cursor.read_u32::<NetworkEndian>()?;
        let stream_dependency = (dependency_with_flag >> 1) << 1;
        let exclusive = dependency_with_flag != stream_dependency;
        let weight = cursor.read_u8()?;

        Ok(TypedFrame::PriorityFrame(
            f.header,
            PriorityHeader {
                stream_dependency,
                exclusive,
                weight,
            },
        ))
    }

    // WINDOW_UPDATE payload format:
    //  +-+-------------------------------------------------------------+
    //  |R|              Window Size Increment (31)                     |
    //  +-+-------------------------------------------------------------+
    fn try_parse_window_update(f: &RawFrame) -> Result<Self, ParseError> {
        if f.payload.len() != 4 {
            return Err(ParseError::FrameSizeError);
        }

        let mut cursor = Cursor::new(&f.payload);
        let increment = cursor.read_u32::<NetworkEndian>()?;
        Ok(TypedFrame::WindowUpdate(f.header, (increment << 1) >> 1))
    }

    fn try_parse_continuation(f: &RawFrame) -> Result<Self, ParseError> {
        let end_headers = flagged(ContinuationFlag::EndHeaders as u8, f.header.raw_flags);

        Ok(TypedFrame::Continuation(
            f.header,
            ContinuationHeader { end_headers },
            try_parse_header_block(&f.payload)?,
        ))
    }

    // PUSH_PROMISE payload format:
    //  +---------------+
    //  |Pad Length? (8)|
    //  +-+-------------+-----------------------------------------------+
    //  |R|                  Promised Stream ID (31)                    |
    //  +-+-----------------------------+-------------------------------+
    //  |                   Header Block Fragment (*)                 ...
    //  +---------------------------------------------------------------+
    //  |                           Padding (*)                       ...
    //  +---------------------------------------------------------------+
    fn try_parse_push_promise(f: &RawFrame) -> Result<Self, ParseError> {
        let padded = flagged(PushPromiseFlags::Padded as u8, f.header.raw_flags);
        let end_headers = flagged(PushPromiseFlags::EndHeaders as u8, f.header.raw_flags);
        let payload = remove_padding(&f.payload, padded)?;

        let mut cursor = Cursor::new(&payload);
        let promised_stream_id = cursor.read_u32::<NetworkEndian>()?;
        let headers = try_parse_header_block(&payload[4..])?;

        Ok(TypedFrame::PushPromise(
            f.header,
            PushPromiseHeaders {
                padded,
                end_headers,
            },
            promised_stream_id,
            headers,
        ))
    }

    // GOAWAY payload format
    //  +-+-------------------------------------------------------------+
    //  |R|                  Last-Stream-ID (31)                        |
    //  +-+-------------------------------------------------------------+
    //  |                      Error Code (32)                          |
    //  +---------------------------------------------------------------+
    //  |                  Additional Debug Data (*)                    |
    //  +---------------------------------------------------------------+
    fn try_parse_goaway(f: &RawFrame) -> Result<Self, ParseError> {
        let mut cursor = Cursor::new(&f.payload);
        let stream_id = cursor.read_u32::<NetworkEndian>()?;
        let error_code = cursor.read_u32::<NetworkEndian>()?;
        let debug_data = String::from_utf8_lossy(&f.payload[8..]);

        Ok(TypedFrame::GoAway(
            f.header,
            stream_id,
            error_code,
            debug_data.to_string(),
        ))
    }

    // PING payload format
    //  +---------------------------------------------------------------+
    //  |                                                               |
    //  |                      Opaque Data (64)                         |
    //  |                                                               |
    //  +---------------------------------------------------------------+
    fn try_parse_ping(f: &RawFrame) -> Result<Self, ParseError> {
        if f.payload.len() != 8 {
            return Err(ParseError::FrameSizeError);
        }

        Ok(TypedFrame::Ping(f.header, f.payload[0..8].into()))
    }

    // RST_STREAM payload format
    //  +---------------------------------------------------------------+
    //  |                        Error Code (32)                        |
    //  +---------------------------------------------------------------+
    fn try_parse_rst_stream(f: &RawFrame) -> Result<Self, ParseError> {
        if f.payload.len() != 4 {
            return Err(ParseError::FrameSizeError);
        }

        let mut cursor = Cursor::new(&f.payload);
        let error_code = cursor.read_u32::<NetworkEndian>()?;

        Ok(TypedFrame::RstStream(f.header, error_code))
    }

    fn try_parse(f: &RawFrame) -> Result<Self, ParseError> {
        match f.header.frame_type {
            FrameType::Data => Self::try_parse_data(f),
            FrameType::Headers => Self::try_parse_headers(f),
            FrameType::Settings => Self::try_parse_settings(f),
            FrameType::Priority => Self::try_parse_priority(f),
            FrameType::WindowUpdate => Self::try_parse_window_update(f),
            FrameType::Continuation => Self::try_parse_continuation(f),
            FrameType::GoAway => Self::try_parse_goaway(f),
            FrameType::Ping => Self::try_parse_ping(f),
            FrameType::PushPromise => Self::try_parse_push_promise(f),
            FrameType::RstStream => Self::try_parse_rst_stream(f),
        }
    }
}

impl Display for FrameHeader {
    fn fmt(self: &Self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let direction = if self.client { ">>" } else { "<<" };
        write!(f, "{} ({}) {}", direction, self.stream_id, self.frame_type)
    }
}

#[test]
fn test_frame_header_display() {
    {
        let f = FrameHeader {
            client: true,
            stream_id: 1,
            frame_type: FrameType::Data,
            raw_flags: 0,
            len: 0,
        };
        assert_eq!(format!("{}", f), ">> (1) DATA");
    }
    let f = FrameHeader {
        client: false,
        stream_id: 2,
        frame_type: FrameType::Headers,
        raw_flags: 0,
        len: 0,
    };
    assert_eq!(format!("{}", f), "<< (2) HEADERS");
}

impl Display for DataHeader {
    fn fmt(self: &Self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        if self.end_stream {
            write!(f, " [end_stream=true]")
        } else {
            Ok(())
        }
    }
}

#[test]
fn test_data_header_display() {
    {
        let f = DataHeader {
            end_stream: false,
            padded: false,
        };
        assert_eq!(format!("{}", f), "");
    }
    let f = DataHeader {
        end_stream: true,
        padded: true,
    };
    assert_eq!(format!("{}", f), " [end_stream=true]");
}

impl Display for HeadersHeader {
    fn fmt(self: &Self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let mut flags = Vec::new();
        if self.end_headers {
            flags.push("end_headers=true");
        }
        if self.end_stream {
            flags.push("end_stream=true");
        }
        if !flags.is_empty() {
            write!(f, "[{}]", flags.join(","))
        } else {
            Ok(())
        }
    }
}

#[test]
fn test_headers_header_display() {
    {
        let f = HeadersHeader {
            priority: false,
            end_stream: false,
            end_headers: false,
            padded: false,
        };
        assert_eq!(format!("{}", f), "");
    }
    let f = HeadersHeader {
        priority: false,
        end_stream: true,
        end_headers: true,
        padded: true,
    };
    assert_eq!(format!("{}", f), "[end_headers=true,end_stream=true]");
}

impl Display for PriorityHeader {
    fn fmt(self: &Self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            " ({}) ({}) ({})",
            self.weight, self.stream_dependency, self.exclusive
        )
    }
}

#[test]
fn test_priority_header_display() {
    {
        let f = PriorityHeader {
            weight: 10,
            stream_dependency: 15,
            exclusive: false,
        };
        assert_eq!(format!("{}", f), " (10) (15) (false)");
    }
    let f = PriorityHeader {
        weight: 10,
        stream_dependency: 15,
        exclusive: true,
    };
    assert_eq!(format!("{}", f), " (10) (15) (true)");
}

impl Display for ContinuationHeader {
    fn fmt(self: &Self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        if self.end_headers {
            write!(f, " [end_headers=true]")
        } else {
            Ok(())
        }
    }
}

#[test]
fn test_continuation_header_display() {
    {
        let f = ContinuationHeader { end_headers: true };
        assert_eq!(format!("{}", f), " [end_headers=true]");
    }
    let f = ContinuationHeader { end_headers: false };
    assert_eq!(format!("{}", f), "");
}

impl Display for SettingsHeader {
    fn fmt(self: &Self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        if self.ack {
            write!(f, " [Ack]")
        } else {
            Ok(())
        }
    }
}

impl Display for PushPromiseHeaders {
    fn fmt(self: &Self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        if self.end_headers {
            write!(f, "[end_headers=true]")
        } else {
            Ok(())
        }
    }
}

#[test]
fn test_settings_header_display() {
    {
        let f = SettingsHeader { ack: true };
        assert_eq!(format!("{}", f), " [Ack]");
    }
    let f = SettingsHeader { ack: false };
    assert_eq!(format!("{}", f), "");
}

impl Display for RawFrame {
    fn fmt(self: &Self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.header)
    }
}

impl Display for TypedFrame {
    fn fmt(self: &Self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            TypedFrame::Data(header, data_header, payload) => {
                write!(f, "{}", header)?;
                writeln!(f, "{}", data_header)?;
                write!(f, "{}", String::from_utf8(payload.clone()).unwrap())
            }
            TypedFrame::Headers(header, header_header, headers) => {
                write!(f, "{} {}{}", header, header_header, headers)
            }
            TypedFrame::PriorityFrame(header, priority_header) => {
                write!(f, "{}", header)?;
                write!(f, "{}", priority_header)
            }
            TypedFrame::SettingsFrame(header, settings_header, settings) => {
                write!(f, "{}", header)?;
                write!(f, "{}", settings_header)?;
                for (identifier, value) in settings {
                    write!(f, "\n{:?}={}", identifier, value)?;
                }
                Ok(())
            }
            TypedFrame::WindowUpdate(header, window_header) => {
                write!(f, "{}", header)?;
                write!(f, " ({})", window_header)
            }
            TypedFrame::Continuation(header, continuation_header, headers) => {
                write!(f, "{} {}{}", header, continuation_header, headers)
            }
            TypedFrame::PushPromise(header, push_promise_header, promised_stream_id, headers) => {
                write!(
                    f,
                    "{} {} ({}){}",
                    header, push_promise_header, promised_stream_id, headers
                )
            }
            TypedFrame::GoAway(header, stream_id, error_code, error_msg) => {
                write!(f, "{} ({}) {}", header, stream_id, error_code)?;
                if !error_msg.is_empty() {
                    write!(f, ": {}", error_msg)
                } else {
                    Ok(())
                }
            }
            TypedFrame::Ping(header, data) => write!(f, "{} {:?}", header, data),
            TypedFrame::RstStream(header, error_code) => write!(f, "{} ({})", header, error_code),
        }
    }
}

#[test]
fn test_typed_frame_display() {
    {
        let f = TypedFrame::Data(
            FrameHeader {
                client: true,
                stream_id: 1,
                len: 2,
                frame_type: FrameType::Data,
                raw_flags: 0,
            },
            DataHeader {
                padded: false,
                end_stream: false,
            },
            "abc".to_string().into(),
        );
        assert_eq!(format!("{}", f), ">> (1) DATA\nabc");
    }

    let f = TypedFrame::Headers(
        FrameHeader {
            client: true,
            stream_id: 1,
            len: 2,
            frame_type: FrameType::Headers,
            raw_flags: 0,
        },
        HeadersHeader {
            priority: true,
            padded: false,
            end_stream: true,
            end_headers: true,
        },
        ParsedHeaders::Full(vec![
            ("a".to_string(), "b".to_string()),
            ("c".to_string(), "d".to_string()),
        ]),
    );
    assert_eq!(
        format!("{}", f),
        ">> (1) HEADERS [end_headers=true,end_stream=true]\na: b\nc: d"
    );

    let f = TypedFrame::PriorityFrame(
        FrameHeader {
            client: true,
            stream_id: 1,
            len: 2,
            frame_type: FrameType::Priority,
            raw_flags: 0,
        },
        PriorityHeader {
            exclusive: true,
            stream_dependency: 100,
            weight: 150,
        },
    );
    assert_eq!(format!("{}", f), ">> (1) PRIORITY (150) (100) (true)");

    let f = TypedFrame::SettingsFrame(
        FrameHeader {
            client: true,
            stream_id: 1,
            len: 2,
            frame_type: FrameType::Settings,
            raw_flags: 0,
        },
        SettingsHeader { ack: true },
        vec![
            (StreamSetting::EnablePush, 0),
            (StreamSetting::InitialWindowSize, 100),
        ],
    );
    assert_eq!(
        format!("{}", f),
        ">> (1) SETTINGS [Ack]\nEnablePush=0\nInitialWindowSize=100"
    );

    let f = TypedFrame::WindowUpdate(
        FrameHeader {
            client: true,
            stream_id: 1,
            len: 2,
            frame_type: FrameType::WindowUpdate,
            raw_flags: 0,
        },
        100,
    );
    assert_eq!(format!("{}", f), ">> (1) WINDOWUPDATE (100)");
}

impl From<Error> for ParseError {
    fn from(e: Error) -> Self {
        ParseError::IoError(e)
    }
}

// TODO add tests for parsing raw HTTP/2 data
impl RawFrame {
    // HTTP/2 Frame layout:
    //  +-----------------------------------------------+
    //  |                 Length (24)                   |
    //  +---------------+---------------+---------------+
    //  |   Type (8)    |   Flags (8)   |
    //  +-+-------------+---------------+-------------------------------+
    //  |R|                 Stream Identifier (31)                      |
    //  +=+=============================================================+
    //  |                   Frame Payload (0...)                      ...
    //  +---------------------------------------------------------------+
    //
    fn try_parse(client: bool, d: &[u8], buf_len: usize) -> Result<(Self, usize), ParseError> {
        // Too small to fit the frame, so cannot be valid.
        if buf_len < 9 {
            return Err(ParseError::TooSmall);
        }

        let mut cursor = Cursor::new(d);
        let len = cursor.read_u24::<NetworkEndian>()?;
        let frame_type = FrameType::try_parse(cursor.read_u8()?)?;
        let flags = cursor.read_u8()?;
        let stream_id = (cursor.read_u32::<NetworkEndian>()? >> 1) << 1; // remove reserved bit

        if (len + 9) as usize > buf_len {
            // We don't have the full payload, so give up.
            // TODO we might want to output at least the raw frame header + a "truncated" string, as this likely
            // means that the payload + header exceeds the size of the bpf buffer used.
            Err(ParseError::IncompleteFrame)
        } else {
            Ok((
                RawFrame {
                    header: FrameHeader {
                        client,
                        len: len as usize,
                        frame_type,
                        raw_flags: flags,
                        stream_id,
                    },
                    payload: d[9..(9 + len as usize)].into(),
                },
                9 + len as usize,
            ))
        }
    }
}

#[test]
fn test_corpus_parsing() {
    let manifest_dir = std::env::vars()
        .find(|(k, _)| k == "CARGO_MANIFEST_DIR")
        .map(|(_, v)| v)
        .unwrap();
    let mut failures = Vec::new();

    let expected_invalid_frames = {
        let mut map = HashMap::new();
        map.insert(
            "5748e7a24e8d9ecb43de7d1e14519f10d8c669a5a2602fc948bc9a80e6114b63",
            ParseError::UnknownFrameType(22),
        );
        map.insert(
            "0b39d9df6e1721030667980a41547272ad42377149edcf130b2bf0b76804c61f",
            ParseError::UnknownFrameType(65),
        );
        map.insert(
            "7232f506e00bee175a3df8d33933fae10c67e501d6cea8e73ce76f4363d0bbea",
            ParseError::UnknownFrameType(22),
        );
        map.insert(
            "d26a0d653a01c6bf9403e0bc0fa5ea05ea4dd7b163e8d85287b19ff257a88ea7",
            ParseError::IncompleteFrame,
        );
        map
    };

    let expected_raw_frames = {
        let mut map = HashMap::new();
        map.insert(
            (
                "e9d399b6dc6b7d18bac97e5556875ab6df561f1ca718f1fc716a929d3c706f14",
                2,
            ),
            ParseError::FrameSizeError,
        );
        map.insert(
            (
                "6e3b8913d874a18ec3ab9f74d4fab435b7738e1a14d0754fb79229c4bda9f604",
                2,
            ),
            ParseError::FrameSizeError,
        );
        map.insert(
            (
                "3376a2cdde0b98759f14490881328f80b5d3c942de3b1304a0382923ce896f8f",
                3,
            ),
            ParseError::ProtocolError("padding exceeds payload".to_string()),
        );
        map.insert(
            (
                "48ca2b3f63206aa8f774c3cb33958a806a1debf3d9ccf7b09c2d31256498cda6",
                3,
            ),
            ParseError::FrameSizeError,
        );
        map.insert(
            (
                "7d230ff71bac867a9820e75328f893972df210ab75cdb67f620b370ee5cddf45",
                2,
            ),
            ParseError::FrameSizeError,
        );
        map.insert(
            (
                "420b9790375f59a6e8c326391023a0981789c2351817996e0c253bfed708ad82",
                2,
            ),
            ParseError::FrameSizeError,
        );
        map.insert(
            (
                "44f3fc1504a14e693fde420da94f77bf4a44e4e741420291491343f7ae4ecc16",
                3,
            ),
            ParseError::FrameSizeError,
        );
        map
    };

    let mut expected_failures = 0;
    for entry in std::fs::read_dir(manifest_dir + "/nghttp_corpus").unwrap() {
        let path = entry.unwrap().path();
        let filename_str = path.as_path().file_name().unwrap().to_str().unwrap();
        let input: Vec<u8> = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) => panic!(
                "failed to read file {:?}: {} (pwd: {:?})",
                path,
                e,
                std::env::current_dir().unwrap()
            ),
        };

        match try_parse_frames(true, &input, input.len()) {
            Ok(frames) => {
                for (i, f) in frames.iter().enumerate() {
                    if let ParseResult::Raw(raw, error) = f {
                        if let Some(err) = expected_raw_frames.get(&(filename_str, i)) {
                            if format!("{:?}", err) == format!("{:?}", error) {
                                expected_failures += 1;
                                continue;
                            }
                        }
                        failures.push(format!(
                            "failed to convert {} {:?} {:?} into typed: {:?}",
                            i, path, raw, error
                        ));
                    }
                }
            }
            Err(e) => {
                if let Some(err) = expected_invalid_frames.get(filename_str) {
                    if format!("{:?}", err) == format!("{:?}", e) {
                        expected_failures += 1;
                        continue;
                    }
                }

                failures.push(format!("failed while processing {:?}: {:?}", path, e))
            }
        }
    }

    for e in &failures {
        eprintln!("{}", e);
    }

    if !failures.is_empty() {
        panic!();
    }

    assert_eq!(
        expected_failures,
        expected_invalid_frames.len() + expected_raw_frames.len()
    );
}

enum ParseResult {
    Typed(TypedFrame),
    Raw(RawFrame, ParseError),
}

fn try_parse_frames(client: bool, data: &[u8], len: usize) -> Result<Vec<ParseResult>, ParseError> {
    // Skip the preamble: this is sent during connection setup for HTTP/2.
    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

    let mut itr = if data[0..preface.len()] == *preface {
        preface.len()
    } else {
        0
    };

    let mut frames = Vec::new();
    // We assume that each data chunk contains zero or more HTTP/2 frames. We attempt
    // to parse it as a typed HTTP/2 frame and print it, falling back to printing information
    // about the raw frame.
    while itr < len as usize {
        let (raw_frame, size) = match RawFrame::try_parse(client, &data[itr..], len - itr) {
            Ok((raw_frame, size)) => (raw_frame, size),
            Err(e) => return Err(e),
        };

        itr += size;

        match TypedFrame::try_parse(&raw_frame) {
            Ok(typed_frame) => frames.push(ParseResult::Typed(typed_frame)),
            Err(e) => frames.push(ParseResult::Raw(raw_frame, e)),
        }
    }

    Ok(frames)
}

pub fn format(data: &bpf::send_data_t) {
    match try_parse_frames(data.bound != 0, &data.buffer, data.msg_size as usize) {
        Ok(frames) => {
            for f in frames {
                match f {
                    ParseResult::Typed(t) => println!("{}", t),
                    ParseResult::Raw(r, e) => println!("{}: {:?}", r, e),
                }
            }
        }
        Err(e) => eprintln!("failed to parse frames: {:?}", e),
    }
}
