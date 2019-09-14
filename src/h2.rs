use super::bpf;
use byteorder::NetworkEndian;
use byteorder::ReadBytesExt;
use hpack::Decoder;
use std::fmt::Display;
use std::io::Cursor;
use std::io::Error;
use std::result::Result;

#[derive(Debug)]
enum ParseError {
    OutOfBounds,
    TooSmall,
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
            _ => Err(ParseError::InvalidFrame("invalid frame type".to_string())),
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

trait PaddableFlag {
    fn padded(flags: u8) -> bool;
}

#[derive(Debug)]
enum DataFlag {
    EndStream = 0x1,
    Padded = 0x8,
}

#[derive(Debug)]
enum HeadersFlag {
    EndStream = 0x1,
    EndHeaders = 0x4,
    Padded = 0x8,
    Priority = 0x20,
}

impl PaddableFlag for HeadersFlag {
    fn padded(flags: u8) -> bool {
        flagged(HeadersFlag::Padded as u8, flags)
    }
}

fn flagged(f: u8, flags: u8) -> bool {
    f & flags != 0
}

#[derive(Copy, Clone)]
struct FrameHeader {
    client: bool,
    len: usize,
    raw_flags: u8,
    frame_type: FrameType,
    stream_id: u32,
}

struct RawFrame {
    header: FrameHeader,
    payload: Vec<u8>,
}

struct DataHeader {
    end_stream: bool,
    padded: bool,
}

struct HeadersHeader {
    end_stream: bool,
    end_headers: bool,
    padded: bool,
    priority: bool,
}

#[derive(Debug)]
enum StreamSetting {
    TableSize = 0x1,
    EnablePush = 0x2,
    MaxConcurrentStreams = 0x3,
    InitialWindowSize = 0x4,
    MaxFrameSize = 0x5,
    MaxHeaderListSize = 0x6,
}

trait ParsableFrame<'a> {
    fn try_parse(f: &'a RawFrame) -> Result<&dyn Display, Error>
    where
        Self: Sized;
}

struct Setting {
    identifier: StreamSetting,
    value: u32,
}

enum SettingFlags {
    Ack = 0x1,
}

struct SettingsHeader {
    ack: bool,
}

struct PriorityHeader {
    stream_dependency: u32,
    exclusive: bool,
    weight: u8,
}

enum TypedFrame {
    Data(FrameHeader, DataHeader, Vec<u8>),
    Headers(FrameHeader, HeadersHeader, Vec<(String, String)>),
    SettingsFrame(FrameHeader, SettingsHeader, Vec<Setting>),
    PriorityFrame(FrameHeader, PriorityHeader),
    WindowUpdate(FrameHeader, u32),
}

fn remove_padding(payload: &[u8], padded: bool) -> Result<Vec<u8>, Error> {
    let (start, stop) = if padded {
        let mut c = Cursor::new(&payload);
        let pad_len = c.read_u32::<NetworkEndian>()?;
        (4, payload.len() - pad_len as usize)
    } else {
        (0, payload.len())
    };

    Ok(payload[start..stop].to_vec())
}

impl TypedFrame {
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

    fn try_parse_headers(f: &RawFrame) -> Result<Self, ParseError> {
        let padded = flagged(HeadersFlag::Padded as u8, f.header.raw_flags);
        let end_stream = flagged(HeadersFlag::EndStream as u8, f.header.raw_flags);
        let end_headers = flagged(HeadersFlag::EndHeaders as u8, f.header.raw_flags);
        let priority = flagged(HeadersFlag::Priority as u8, f.header.raw_flags); // TODO handle this
        let payload = remove_padding(&f.payload, padded)?;

        let mut d = Decoder::new();
        let headers = match d.decode(&payload) {
            Ok(decoded) => {
                let mut headers = Vec::new();
                for (key, value) in decoded {
                    let key_str = String::from_utf8(key)
                        .map_err(|_| Error::new(std::io::ErrorKind::Other, "invalid header key"))?;
                    let value_str = String::from_utf8(value)
                        .map_err(|_| Error::new(std::io::ErrorKind::Other, "invalid header key"))?;

                    headers.push((key_str, value_str));
                }
                Ok(headers)
            }
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "invalid hpack encoding",
            )),
        }?;

        Ok(TypedFrame::Headers(
            f.header,
            HeadersHeader {
                padded,
                end_stream,
                end_headers,
                priority,
            },
            headers,
        ))
    }

    fn try_parse_settings(f: &RawFrame) -> Result<Self, ParseError> {
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
                _ => {
                    return Err(ParseError::InvalidFrame(
                        "invalid settings identifier".to_string(),
                    ))
                }
            };

            let value = cursor.read_u32::<NetworkEndian>()?;
            settings.push(Setting { value, identifier });
        }

        let ack = flagged(SettingFlags::Ack as u8, f.header.raw_flags);
        Ok(TypedFrame::SettingsFrame(
            f.header,
            SettingsHeader { ack },
            settings,
        ))
    }

    fn try_parse_priority(f: &RawFrame) -> Result<Self, ParseError> {
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

    fn try_parse_window_update(f: &RawFrame) -> Result<Self, ParseError> {
        let mut cursor = Cursor::new(&f.payload);
        let increment = cursor.read_u32::<NetworkEndian>()?;
        Ok(TypedFrame::WindowUpdate(f.header, (increment << 1) >> 1))
    }

    fn try_parse(f: &RawFrame) -> Result<Self, ParseError> {
        match f.header.frame_type {
            FrameType::Data => Self::try_parse_data(f),
            FrameType::Headers => Self::try_parse_headers(f),
            FrameType::Settings => Self::try_parse_settings(f),
            FrameType::Priority => Self::try_parse_priority(f),
            FrameType::WindowUpdate => Self::try_parse_window_update(f),
            _ => panic!(),
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
            write!(f, " [{}]", flags.join(","))
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
    assert_eq!(format!("{}", f), " [end_headers=true,end_stream=true]");
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

impl Display for SettingsHeader {
    fn fmt(self: &Self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        if self.ack {
            write!(f, " [Ack]")
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
                write!(f, "{}", header)?;
                write!(f, "{}", header_header)?;
                for (key, value) in headers {
                    write!(f, "\n{}: {}", key, value)?;
                }
                Ok(())
            }
            TypedFrame::PriorityFrame(header, priority_header) => {
                write!(f, "{}", header)?;
                write!(f, "{}", priority_header)
            }
            TypedFrame::SettingsFrame(header, settings_header, settings) => {
                write!(f, "{}", header)?;
                write!(f, "{}", settings_header)?;
                for setting in settings {
                    write!(f, "\n{:?}={}", setting.identifier, setting.value)?;
                }
                Ok(())
            }
            TypedFrame::WindowUpdate(header, window_header) => {
                write!(f, "{}", header)?;
                write!(f, " ({})", window_header)
            }
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
        HashMap::from_iter(vec![
            ("a".to_string(), "b".to_string()),
            ("c".to_string(), "d".to_string()),
        ]),
    );
    assert_eq!(
        format!("{}", f),
        ">> (1) HEADERS [end_headers=true,end_stream=true]\na: b\nc: d\n"
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
            Setting {
                identifier: StreamSetting::EnablePush,
                value: 0,
            },
            Setting {
                identifier: StreamSetting::InitialWindowSize,
                value: 100,
            },
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

impl RawFrame {
    fn try_parse(client: bool, d: &[u8], buf_len: usize) -> Result<(Self, usize), ParseError> {
        if buf_len < 9 {
            return Err(ParseError::TooSmall);
        }

        let mut cursor = Cursor::new(d);
        let len = cursor.read_u24::<NetworkEndian>()?;
        let frame_type = FrameType::try_parse(cursor.read_u8()?)?;
        let flags = cursor.read_u8()?;
        let stream_id = (cursor.read_u32::<NetworkEndian>()? >> 1) << 1; // remove reserved bit

        if (len + 9) as usize > buf_len {
            Err(ParseError::OutOfBounds)
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

pub fn format(data: &bpf::send_data_t) {
    // Skip the preamble: this is sent during connection setup for HTTP/2.
    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

    let mut itr = if data.buffer[0..preface.len()] == *preface {
        preface.len()
    } else {
        0
    };

    // We assume that each data chunk contains zero or more HTTP/2 frames. We attempt
    // to parse it as a typed HTTP/2 frame and print it, falling back to printing information
    // about the raw frame.
    while itr < data.msg_size as usize {
        let (raw_frame, size) = match RawFrame::try_parse(
            data.bound == 0,
            &data.buffer[itr..],
            data.msg_size as usize - itr,
        ) {
            Err(e) => {
                // Invalid frame, skip output.
                eprintln!("failed to parse frame {:?}", e);
                return;
            }
            Ok((raw_frame, size)) => (raw_frame, size),
        };

        itr += size;

        if let Ok(typed_frame) = TypedFrame::try_parse(&raw_frame) {
            println!("{}", typed_frame);
        } else {
            println!("{}", raw_frame);
        }
    }
}
