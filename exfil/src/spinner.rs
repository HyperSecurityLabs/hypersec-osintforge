/// An async terminal spinner using braille characters.
/// Displays an animated spinner on stderr while a task runs,
/// then replaces it with a static status line.
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Braille frame characters for the spinner animation.
const BRAILLE: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// A lightweight spinner that runs in a tokio background task.
pub struct Spinner {
    running: Arc<AtomicBool>,
    msg: String,
}

impl Spinner {
    /// Start a new spinner with the given message text.
    pub fn start(msg: &str) -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let flag = running.clone();
        let task_msg = msg.to_string();

        // Step: spawn async spinner task
        tokio::spawn(async move {
            let mut i = 0;
            // Loop: animate spinner
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

    /// Stop the spinner and print the final status indicator.
    pub fn stop(&self, status: &str) {
        self.running.store(false, Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(100));
        let _ = writeln!(io::stderr(), "  {} {}", status, self.msg);
    }
}
