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

fn remove_padding(payload: &Vec<u8>, padded: bool) -> Vec<u8> {
    let (start, stop) = if padded {
        let mut c = Cursor::new(&payload);
        let pad_len = c.read_u32::<NetworkEndian>().unwrap();
        (4, payload.len() - pad_len as usize)
    } else {
        (0, payload.len())
    };

    payload[start..stop].to_vec()
}

impl From<&Frame> for DataFrame {
    fn from(f: &Frame) -> Self {
        let padded = flagged(DataFlag::Padded as u8, f.flags);

        DataFrame {
            stream_id: f.stream_id,
            end_stream: flagged(DataFlag::EndStream as u8, f.flags),
            padded,
            payload: remove_padding(&f.payload, padded),
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
        let padded = flagged(HeadersFlag::Padded as u8, f.flags);

        HeadersFrame {
            stream_id: f.stream_id,
            end_stream: flagged(HeadersFlag::EndStream as u8, f.flags),
            end_headers: flagged(HeadersFlag::EndHeaders as u8, f.flags),
            priority: flagged(HeadersFlag::Priority as u8, f.flags), // TODO handle this
            padded,
            payload: remove_padding(&f.payload, padded),
        }
    }
}

fn display_prefix(
    f: &Frame,
    flags: &str,
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
    };

    display_prefix(&r, &flags, formatter)?;

    writeln!(formatter)?;
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
    writeln!(formatter)?;
    let mut d = Decoder::new();
    match d.decode(&f.payload) {
        Ok(decoded) => {
            for (key, value) in decoded {
                writeln!(
                    formatter,
                    "{}: {}",
                    String::from_utf8(key).unwrap(),
                    String::from_utf8(value).unwrap()
                )?;
            }
            Ok(())
        }
        Err(_) => Err(std::fmt::Error),
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
                    client,
                    len: len as usize,
                    frame_type,
                    flags,
                    stream_id,
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
