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
    InvalidFrame,
    IoError(std::io::Error),
}

#[derive(Debug, PartialEq)]
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
            _ => Err(ParseError::InvalidFrame),
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

struct DataFlags {
    end_stream: bool,
    padded: bool,
}

impl DataFlags {
    fn new(flags: u8) -> Self {
        DataFlags {
            end_stream: flags & 0x1 != 0,
            padded: flags & 0x8 != 0,
        }
    }
}

impl Display for DataFlags {
    fn fmt(self: &Self, formatter: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        if self.end_stream {
            return write!(formatter, "[e]");
        }

        Ok(())
    }
}

#[derive(Debug)]
struct Frame {
    client: bool,
    len: usize,
    frame_type: FrameType, // turn into enum
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
}

#[derive(Debug)]
struct DataFrame {
    stream_id: u32,
    end_stream: bool,
    padded: bool,
    payload: Vec<u8>,
}

impl From<&Frame> for DataFrame {
    fn from(f: &Frame) -> Self {
        let padded = f.flags & 0x8 != 0;

        let (start, stop) = if padded {
            let mut c = Cursor::new(&f.payload);
            let pad_len = c.read_u32::<NetworkEndian>().unwrap();
            (4, f.len - pad_len as usize)
        } else {
            (0, f.len)
        };

        DataFrame {
            stream_id: f.stream_id,
            end_stream: f.flags & 0x1 != 0,
            padded: padded,
            payload: f.payload[start..stop].to_vec(),
        }
    }
}

#[derive(Debug)]
struct HeadersFrame {
    stream_id: u32,
    end_stream: bool,
    end_headers: bool,
    padded: bool,
    priority: bool,
    payload: Vec<u8>,
}

impl From<&Frame> for HeadersFrame {
    fn from(f: &Frame) -> Self {
        let padded = f.flags & 0x8 != 0;

        // TODO dry up padding handling
        let (start, stop) = if padded {
            let mut c = Cursor::new(&f.payload);
            let pad_len = c.read_u32::<NetworkEndian>().unwrap();
            (4, f.len - pad_len as usize)
        } else {
            (0, f.len)
        };

        HeadersFrame {
            stream_id: f.stream_id,
            end_stream: f.flags & 0x1 != 0,
            end_headers: f.flags & 0x4 != 0,
            priority: f.flags & 0x20 != 0, // TODO handle this
            padded: padded,
            payload: f.payload[start..stop].to_vec(),
        }
    }
}

fn display_prefix(
    f: &Frame,
    flags: &String,
    formatter: &mut std::fmt::Formatter<'_>,
) -> Result<(), std::fmt::Error> {
    let direction = if f.client { ">>" } else { "<<" };
    write!(
        formatter,
        "{} ({}) {} {}",
        direction, f.stream_id, f.frame_type, flags
    )
}

fn display_data(
    r: &Frame,
    f: &DataFrame,
    formatter: &mut std::fmt::Formatter<'_>,
) -> Result<(), std::fmt::Error> {
    let flags = if f.end_stream {
        "[end_stream=true]"
    } else {
        ""
    }
    .to_string();

    display_prefix(&r, &flags, formatter)?;

    write!(formatter, "\n")?;
    write!(
        formatter,
        "{}",
        String::from_utf8(f.payload.clone()).unwrap()
    )
}

fn display_headers(
    r: &Frame,
    f: &HeadersFrame,
    formatter: &mut std::fmt::Formatter<'_>,
) -> Result<(), std::fmt::Error> {
    let mut flags = Vec::new();
    if f.end_headers {
        flags.push("end_headers=true");
    }
    if f.end_stream {
        flags.push("end_stream=true");
    }
    let flag_str = if flags.is_empty() {
        "".to_string()
    } else {
        format!("[{}]", flags.join(","))
    };
    display_prefix(&r, &flag_str, formatter)?;
    write!(formatter, "\n")?;
    let mut d = hpack::Decoder::new();
    match d.decode(&f.payload) {
        Ok(decoded) => {
            for (key, value) in decoded {
                write!(
                    formatter,
                    "{}: {}\n",
                    String::from_utf8(key).unwrap(),
                    String::from_utf8(value).unwrap()
                )?;
            }
            Ok(())
        }
        Err(e) => Err(std::fmt::Error),
    }
}

impl Display for Frame {
    fn fmt(self: &Self, formatter: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self.frame_type {
            FrameType::Data => display_data(self, &DataFrame::from(self), formatter),
            FrameType::Headers => display_headers(&self, &HeadersFrame::from(self), formatter),
            _ => display_prefix(&self, &"".to_string(), formatter),
        }
    }
}

impl From<Error> for ParseError {
    fn from(e: Error) -> Self {
        ParseError::IoError(e)
    }
}

impl Frame {
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
                Frame {
                    client: client,
                    len: len as usize,
                    frame_type: frame_type,
                    flags: flags,
                    stream_id: stream_id,
                    payload: d[9..(9 + len as usize)].into(),
                },
                9 + len as usize,
            ))
        }
    }
}

pub fn format(data: &bpf::send_data_t) {
    // skip preamble
    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

    let mut itr = if data.buffer[0..preface.len()] == *preface {
        preface.len()
    } else {
        0
    };

    while itr < data.msg_size as usize {
        match Frame::try_parse(
            data.bound == 0,
            &data.buffer[itr..],
            data.msg_size as usize - itr,
        ) {
            Err(e) => {
                eprintln!("failed to parse frame {:?}", e);
                return;
            }
            Ok((frame, size)) => {
                println! {"{}", frame};
                itr += size;
            }
        }
    }
}
