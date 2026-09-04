/// A simple terminal spinner for async operations.
///
/// Displays an animated braille spinner on stderr while a task is running,
/// then replaces the spinner line with a status message on completion.
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Braille spinner frames for the animation cycle.
const BRAILLE: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// A terminal spinner that renders on stderr.
pub struct Spinner {
    running: Arc<AtomicBool>,
    msg: String,
}

impl Spinner {
    /// Start a new spinner with the given status message.
    ///
    /// Spawns a background task that animates the spinner until `stop` is called.
    pub fn start(msg: &str) -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let flag = running.clone();
        let task_msg = msg.to_string();

        tokio::spawn(async move {
            let mut i = 0;
            // Loop: animate spinner frames
            while flag.load(Ordering::Relaxed) {
                let frame = BRAILLE[i % BRAILLE.len()];
                let _ = write!(io::stderr(), "\r  {} {}", frame, task_msg);
                let _ = io::stderr().flush();
                tokio::time::sleep(Duration::from_millis(80)).await;
                i += 1;
            }
            // Handle: clear the spinner line
            let _ = write!(io::stderr(), "\r  {}\n", " ".repeat(task_msg.len() + 4));
            let _ = io::stderr().flush();
        });

        Spinner { running, msg: msg.to_string() }
    }

    /// Stop the spinner and display a status indicator.
    pub fn stop(&self, status: &str) {
        // Step: signal the animation task to stop
        self.running.store(false, Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(100));
        // Handle: write final status line
        let _ = writeln!(io::stderr(), "  {} {}", status, self.msg);
    }
}
