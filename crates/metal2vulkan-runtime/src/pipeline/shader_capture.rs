//! Opt-in, bounded diagnostic export of the SPIR-V handed to a Vulkan shader module.
//! This is not a complete Vulkan pipeline trace and does not reproduce its state.
use metal2vulkan::pipeline::StageModule;
use sha2::{Digest, Sha256};
use std::ffi::{c_char, CString};
use std::fmt::Write;
use std::io::Write as IoWrite;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::sync::{mpsc, Arc};

const MAX_WORDS: usize = 8192;
const MAX_CAPTURES: usize = 4;
const CHUNK_WORDS: usize = 32;
static OBSERVED: AtomicUsize = AtomicUsize::new(0);
static OUTPUT: OnceLock<extern "C" fn(*const c_char) -> i32> = OnceLock::new();

/// Set the optional diagnostic transport. An already-registered transport remains in use.
#[no_mangle]
pub extern "C" fn metal2vulkan_shader_capture_set_output(
    output: extern "C" fn(*const c_char) -> i32,
) {
    let _ = OUTPUT.set(output);
}

fn enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(metal2vulkan::env_vars::capture_spirv)
}

fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut text, "{byte:02x}").expect("writing a String cannot fail");
    }
    text
}

fn frame(
    words: &[u32],
    entry: &str,
    stage: &str,
    pid: u32,
    id: usize,
    mut emit: impl FnMut(String) -> bool,
) -> bool {
    if words.len() > MAX_WORDS || words.len() < 5 || words[0] != 0x0723_0203 || entry.len() > 256 {
        return false;
    }
    let mut digest = Sha256::new();
    digest.update(b"m2vspv1\0");
    digest.update(pid.to_le_bytes());
    digest.update((id as u64).to_le_bytes());
    digest.update((words.len() as u32).to_le_bytes());
    for field in [stage.as_bytes(), entry.as_bytes(), b"missing".as_slice()] {
        digest.update((field.len() as u32).to_le_bytes());
        digest.update(field);
    }
    for word in words {
        digest.update(word.to_le_bytes());
    }
    let sha = hex(&digest.finalize());
    if !emit(format!("m2vspv1 begin pid={pid} id={id} words={} sha256={sha} stage={stage} entryhex={} pipeline=missing", words.len(), hex(entry.as_bytes()))) {
        return false;
    }
    for (offset, chunk) in words.chunks(CHUNK_WORDS).enumerate() {
        let mut data = String::with_capacity(chunk.len() * 8);
        for word in chunk {
            data.push_str(&hex(&word.to_le_bytes()));
        }
        if !emit(format!(
            "m2vspv1 data pid={pid} id={id} offset={} hex={data}",
            offset * CHUNK_WORDS
        )) {
            return false;
        }
    }
    emit(format!(
        "m2vspv1 end pid={pid} id={id} words={} sha256={sha}",
        words.len()
    ))
}

struct Captured {
    words: Arc<[u32]>,
    entry: String,
    stage: String,
    id: usize,
}

fn worker(recv: mpsc::Receiver<Captured>, mut output: impl FnMut(String) -> bool) {
    while let Ok(capture) = recv.recv() {
        if !frame(
            &capture.words,
            &capture.entry,
            &capture.stage,
            std::process::id(),
            capture.id,
            &mut output,
        ) {
            break;
        }
    }
}

fn sender() -> Option<&'static mpsc::SyncSender<Captured>> {
    static SENDER: OnceLock<Option<mpsc::SyncSender<Captured>>> = OnceLock::new();
    SENDER
        .get_or_init(|| {
            let (send, recv) = mpsc::sync_channel::<Captured>(MAX_CAPTURES);
            std::thread::Builder::new()
                .name("m2v-spirv-capture".into())
                .spawn(move || {
                    worker(recv, |line| {
                        if let Some(callback) = OUTPUT.get() {
                            if let Ok(line) = CString::new(line) {
                                callback(line.as_ptr()) == 0
                            } else {
                                false
                            }
                        } else {
                            writeln!(std::io::stderr().lock(), "{line}").is_ok()
                        }
                    })
                })
                .ok()
                .map(|_| send)
        })
        .as_ref()
}

pub(super) fn capture(stage: &StageModule) {
    if !enabled() {
        return;
    }
    static START: OnceLock<Option<usize>> = OnceLock::new();
    let Some(start) = *START.get_or_init(metal2vulkan::env_vars::capture_spirv_start) else {
        return;
    };
    let Ok(id) = OBSERVED.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
    else {
        return;
    };
    if id < start
        || id - start >= MAX_CAPTURES
        || stage.spirv.len() > MAX_WORDS
        || stage.spirv.len() < 5
        || stage.spirv[0] != 0x0723_0203
        || stage.entry_point.len() > 256
    {
        return;
    }
    let Some(sender) = sender() else {
        return;
    };
    let _ = sender.try_send(Captured {
        words: Arc::clone(&stage.spirv),
        entry: stage.entry_point.clone(),
        stage: format!("{:?}", stage.stage),
        id,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn host_roundtrip_fixture() {
        let mut words = vec![0x0723_0203, 0x0001_0500, 0, 128, 0];
        words.extend(0..100);
        assert!(frame(&words, "main", "Vertex", 99, 7, |line| {
            println!("{line}");
            true
        }));
    }

    #[test]
    fn output_failure_stops_worker_and_queued_capture() {
        let (send, recv) = mpsc::sync_channel(2);
        for id in 0..2 {
            send.send(Captured {
                words: Arc::from([0x0723_0203, 0x0001_0500, 0, 8, 0]),
                entry: "main".into(),
                stage: "Vertex".into(),
                id,
            })
            .unwrap();
        }
        drop(send);
        let mut calls = 0;
        worker(recv, |_| {
            calls += 1;
            calls != 2
        });
        assert_eq!(calls, 2);
    }

    #[test]
    fn output_failure_stops_remaining_frame() {
        let words = [0x0723_0203, 0x0001_0500, 0, 8, 0, 0x0102_0304];
        let mut calls = 0;
        assert!(!frame(&words, "main", "Vertex", 10, 3, |_| {
            calls += 1;
            calls != 2
        }));
        assert_eq!(calls, 2);
    }

    #[test]
    fn bounded_framing_preserves_little_endian_words() {
        let words = [0x0723_0203, 0x0001_0500, 0, 8, 0, 0x0102_0304];
        let mut lines = Vec::new();
        assert!(frame(&words, "main", "Vertex", 10, 3, |line| {
            lines.push(line);
            true
        }));
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("entryhex=6d61696e pipeline=missing"));
        assert!(lines[1].ends_with("030223070005010000000000080000000000000004030201"));
        assert!(lines[2].starts_with("m2vspv1 end pid=10 id=3 words=6 sha256="));
        lines.clear();
        assert!(!frame(
            &vec![0; MAX_WORDS + 1],
            "main",
            "Vertex",
            10,
            4,
            |line| {
                lines.push(line);
                true
            }
        ));
        assert!(lines.is_empty());
    }
}
