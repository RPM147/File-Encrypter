//! Bounded in-memory byte pipe connecting tar packaging/unpacking directly to
//! v5 Chunked AEAD streaming without ever touching plaintext temp files on disk.

use std::io::{self, Read, Write};
use std::sync::mpsc::{self, Receiver, SyncSender};
use zeroize::Zeroizing;

pub struct PipeWriter {
    tx: Option<SyncSender<Zeroizing<Vec<u8>>>>,
}

pub struct PipeReader {
    rx: Receiver<Zeroizing<Vec<u8>>>,
    current: Zeroizing<Vec<u8>>,
    pos: usize,
}

pub fn bounded_pipe(capacity: usize) -> (PipeWriter, PipeReader) {
    let (tx, rx) = mpsc::sync_channel(capacity);
    (
        PipeWriter { tx: Some(tx) },
        PipeReader {
            rx,
            current: Zeroizing::new(Vec::new()),
            pos: 0,
        },
    )
}

impl Write for PipeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let tx = self
            .tx
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "pipe closed"))?;
        tx.send(Zeroizing::new(buf.to_vec()))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "reader dropped"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for PipeWriter {
    fn drop(&mut self) {
        self.tx.take();
    }
}

impl Read for PipeReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        while self.pos >= self.current.len() {
            match self.rx.recv() {
                Ok(next) => {
                    self.current = next;
                    self.pos = 0;
                }
                Err(_) => return Ok(0), // Writer dropped -> EOF
            }
        }
        let avail = self.current.len() - self.pos;
        let take = avail.min(out.len());
        out[..take].copy_from_slice(&self.current[self.pos..self.pos + take]);
        self.pos += take;
        Ok(take)
    }
}
