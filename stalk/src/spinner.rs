/// Terminal spinner for long-running STALK operations.
///
/// Uses braille-pattern animation on stderr and clears the line on stop.
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Braille spinner frames for a smooth animated indicator.
const BRAILLE: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// A cancellable terminal spinner that runs on a background tokio task.
pub struct Spinner {
    running: Arc<AtomicBool>,
    msg: String,
}

impl Spinner {
    /// Start a new spinner with a descriptive message.
    ///
    /// Spawns a tokio task that writes animated braille frames to
    /// stderr until [`Spinner::stop`] is called.
    pub fn start(msg: &str) -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let flag = running.clone();
        let task_msg = msg.to_string();

        // Step: Spawn async spinner task
        tokio::spawn(async move {
            let mut i = 0;
            // Loop: Animate until stop signal received
            while flag.load(Ordering::Relaxed) {
                let frame = BRAILLE[i % BRAILLE.len()];
                let _ = write!(io::stderr(), "\r  {} {}", frame, task_msg);
                let _ = io::stderr().flush();
                tokio::time::sleep(Duration::from_millis(80)).await;
                i += 1;
            }
            // Step: Clear spinner line on completion
            let _ = write!(io::stderr(), "\r  {}\n", " ".repeat(task_msg.len() + 4));
            let _ = io::stderr().flush();
        });

        Spinner { running, msg: msg.to_string() }
    }

    /// Stop the spinner and print the final status with message.
    pub fn stop(&self, status: &str) {
        // Step: Signal spinner to halt
        self.running.store(false, Ordering::Relaxed);
        // Step: Brief pause for the task to flush
        std::thread::sleep(Duration::from_millis(100));
        let _ = writeln!(io::stderr(), "  {} {}", status, self.msg);
    }
}
