/// Auspex — Terminal Spinner
///
/// Provides a lightweight animated spinner for terminal feedback
/// during long-running WHOIS, RDAP, and DNS operations.
///
/// Author: khaninkali • HyperSecurity Offensive Labs

use colored::Colorize;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// A simple terminal spinner with start/stop lifecycle.
pub struct Spinner {
    running: Arc<AtomicBool>,
    message: String,
}

impl Spinner {
    /// Starts a new spinner with the given status message.
    pub fn start(message: &str) -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();
        let msg = message.to_string();
        let msg_for_closure = msg.clone();

        // Spawn a background thread for spinner animation
        thread::spawn(move || {
            let frames = ["◜", "◝", "◞", "◟"];
            let mut i = 0;
            while r.load(Ordering::Relaxed) {
                let frame = frames[i % frames.len()];
                print!("\r  {} {}", frame.cyan(), msg_for_closure.dimmed());
                io::stdout().flush().ok();
                thread::sleep(Duration::from_millis(80));
                i += 1;
            }
            print!("\r");
            io::stdout().flush().ok();
        });

        Spinner { running, message: msg }
    }

    /// Stops the spinner and displays a completion symbol.
    pub fn stop(&self, symbol: &str) {
        self.running.store(false, Ordering::Relaxed);
        thread::sleep(Duration::from_millis(100));
        println!(
            "  {} {}",
            format!("{}", symbol).cyan().bold(),
            self.message.dimmed()
        );
    }
}
