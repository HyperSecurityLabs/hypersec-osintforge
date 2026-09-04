/// SPOOF — Terminal Spinner
///
/// Provides an animated braille spinner for terminal feedback
/// during long-running DNS lookups and SMTP relay tests.
///
/// Author: khaninkali • HyperSecurity Offensive Labs

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

const BRAILLE: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// A terminal spinner with async-compatible animation.
pub struct Spinner {
    running: Arc<AtomicBool>,
    msg: String,
}

impl Spinner {
    /// Starts a new spinner with the given status message.
    pub fn start(msg: &str) -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let flag = running.clone();
        let task_msg = msg.to_string();

        tokio::spawn(async move {
            let mut i = 0;
            while flag.load(Ordering::Relaxed) {
                let frame = BRAILLE[i % BRAILLE.len()];
                let _ = write!(io::stderr(), "\r  {} {}", frame, task_msg);
                let _ = io::stderr().flush();
                tokio::time::sleep(Duration::from_millis(80)).await;
                i += 1;
            }
            let _ = write!(io::stderr(), "\r  {}\n", " ".repeat(task_msg.len() + 4));
            let _ = io::stderr().flush();
        });

        Spinner { running, msg: msg.to_string() }
    }

    /// Stops the spinner and displays a status symbol.
    pub fn stop(&self, status: &str) {
        self.running.store(false, Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(100));
        let _ = writeln!(io::stderr(), "  {} {}", status, self.msg);
    }
}
