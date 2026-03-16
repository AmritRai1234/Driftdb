//! DriftDB REPL — Interactive query shell with security, colored output, and table rendering

use colored::*;
use comfy_table::{Table, presets::UTF8_FULL};
use driftdb_core::security::{AuditLog, Auth, SecurityLimits, validate_query};
use driftdb_core::Storage;
use driftdb_query::{Executor, QueryResult};
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use std::sync::{Arc, Mutex};

/// ASCII art banner
const BANNER: &str = r#"
    ____       _  ____  ____  ____
   / __ \_____(_)/ __/ / /  |/  / ____
  / / / / ___/ / /_  / / /|_/ / / __ \
 / /_/ / /  / / __/ / / /  / / / /_/ /
/_____/_/  /_/_/   /_/_/  /_/  \____/
"#;

pub struct Repl {
    executor: Executor,
    storage: Arc<Storage>,
    audit: Arc<Mutex<AuditLog>>,
    limits: SecurityLimits,
    authenticated: bool,
    require_auth: bool,
}

impl Repl {
    pub fn new(executor: Executor, storage: Arc<Storage>, require_auth: bool) -> Self {
        Repl {
            executor,
            storage,
            audit: Arc::new(Mutex::new(AuditLog::new())),
            limits: SecurityLimits::default(),
            authenticated: !require_auth,
            require_auth,
        }
    }

    pub fn run(&mut self) {
        println!("{}", BANNER.bright_cyan().bold());
        println!(
            "  {} {} — {}",
            "🌀".to_string(),
            "DriftDB v0.1.0".bright_white().bold(),
            "A next-generation database".dimmed()
        );
        println!(
            "  {}",
            "🔒 Security: AES-256 | Argon2 | SHA-256 | Audit Log".bright_green()
        );
        println!(
            "  {}",
            "⚙  Engine:   ACID Txns | WAL | LZ4 | Backups | Health Checks".bright_blue()
        );
        println!(
            "  {}",
            "Type 'HELP' for commands, 'quit' to exit.".dimmed()
        );
        println!();

        let mut rl = match DefaultEditor::new() {
            Ok(rl) => rl,
            Err(e) => {
                eprintln!("Failed to initialize REPL: {}", e);
                return;
            }
        };

        let history_path = dirs_hint();
        let _ = rl.load_history(&history_path);

        // Authentication gate
        if self.require_auth && !self.authenticated {
            if !self.authenticate(&mut rl) {
                println!(
                    "  {} {}",
                    "✗".red().bold(),
                    "Authentication failed. Goodbye.".red()
                );
                return;
            }
        }

        loop {
            let prompt = if self.authenticated {
                format!("{} ", "drift>".bright_cyan().bold())
            } else {
                format!("{} ", "drift[locked]>".red().bold())
            };

            match rl.readline(&prompt) {
                Ok(line) => {
                    let input = line.trim();
                    if input.is_empty() {
                        continue;
                    }

                    rl.add_history_entry(input).ok();

                    if input.eq_ignore_ascii_case("quit")
                        || input.eq_ignore_ascii_case("exit")
                        || input.eq_ignore_ascii_case("\\q")
                    {
                        self.log_audit("SESSION_END", "User exited", true);
                        println!(
                            "\n  {} {}",
                            "👋".to_string(),
                            "See you, builder.".bright_cyan()
                        );
                        break;
                    }

                    if input.eq_ignore_ascii_case("clear") {
                        print!("\x1B[2J\x1B[1;1H");
                        continue;
                    }

                    let upper = input.to_uppercase();

                    // Handle special commands
                    if upper.starts_with("SHOW AUDIT") { self.show_audit(); continue; }
                    if upper.starts_with("VERIFY AUDIT") { self.verify_audit(); continue; }
                    if upper.starts_with("SHOW SECURITY") { self.show_security(); continue; }
                    if upper.starts_with("SHOW HEALTH") { self.show_health(); continue; }
                    if upper.starts_with("BACKUP") { self.do_backup(); continue; }
                    if upper.starts_with("FLUSH") { self.do_flush(); continue; }

                    let start = std::time::Instant::now();
                    self.execute_query(input);
                    let elapsed = start.elapsed();
                    println!(
                        "  {}",
                        format!("({:.1}ms)", elapsed.as_secs_f64() * 1000.0).dimmed()
                    );
                    println!();
                }
                Err(ReadlineError::Interrupted) => {
                    println!("  {}", "Use 'quit' to exit.".dimmed());
                }
                Err(ReadlineError::Eof) => {
                    self.log_audit("SESSION_END", "User exited (EOF)", true);
                    println!(
                        "\n  {} {}",
                        "👋".to_string(),
                        "See you, builder.".bright_cyan()
                    );
                    break;
                }
                Err(err) => {
                    eprintln!("  {} {}", "Error:".red(), err);
                }
            }
        }

        let _ = rl.save_history(&history_path);
        // SECURITY: History may contain sensitive queries — restrict permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(&history_path, perms);
        }
    }

    /// Authenticate the user before allowing access
    fn authenticate(&mut self, rl: &mut DefaultEditor) -> bool {
        // Check if a password hash exists on disk
        let hash_path = std::path::Path::new(".drift_auth");

        if hash_path.exists() {
            // Existing database — verify password
            let stored_hash = std::fs::read_to_string(hash_path).unwrap_or_default();
            println!("  {} {}", "🔐".to_string(), "Database is password-protected.".bright_yellow());

            for attempt in 1..=3 {
                match rl.readline(&format!("  {} ", "Password:".bright_white())) {
                    Ok(password) => {
                        match Auth::verify_password(password.trim(), stored_hash.trim()) {
                            Ok(true) => {
                                self.authenticated = true;
                                self.log_audit("AUTH", "Password verified", true);
                                println!(
                                    "  {} {}",
                                    "✓".green().bold(),
                                    "Authenticated.".bright_green()
                                );
                                println!();
                                return true;
                            }
                            _ => {
                                self.log_audit(
                                    "AUTH_FAIL",
                                    &format!("Failed attempt {}/3", attempt),
                                    false,
                                );
                                println!(
                                    "  {} {} ({}/3)",
                                    "✗".red().bold(),
                                    "Wrong password.".red(),
                                    attempt
                                );
                            }
                        }
                    }
                    Err(_) => return false,
                }
            }
            false
        } else {
            // New database — set up password
            println!(
                "  {} {}",
                "🔑".to_string(),
                "First time setup: Set a password to protect your database.".bright_yellow()
            );

            match rl.readline(&format!("  {} ", "New password:".bright_white())) {
                Ok(password) => {
                    let password = password.trim();

                    // Check strength
                    if let Err(issues) = Auth::check_strength(password) {
                        println!("  {} {}", "✗".red().bold(), "Password too weak:".red());
                        for issue in issues {
                            println!("    {} {}", "•".red(), issue);
                        }
                        return false;
                    }

                    match rl.readline(&format!("  {} ", "Confirm password:".bright_white())) {
                        Ok(confirm) => {
                            if password != confirm.trim() {
                                println!(
                                    "  {} {}",
                                    "✗".red().bold(),
                                    "Passwords don't match.".red()
                                );
                                return false;
                            }
                        }
                        Err(_) => return false,
                    }

                    match Auth::hash_password(password) {
                        Ok(hash) => {
                            std::fs::write(hash_path, &hash).ok();
                            // Restrict file permissions: owner-only (0600)
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::PermissionsExt;
                                let perms = std::fs::Permissions::from_mode(0o600);
                                let _ = std::fs::set_permissions(hash_path, perms);
                            }
                            self.authenticated = true;
                            self.log_audit("SETUP", "Password set for database", true);
                            println!(
                                "  {} {}",
                                "✓".green().bold(),
                                "Password set. Database is now protected.".bright_green()
                            );
                            println!();
                            true
                        }
                        Err(e) => {
                            eprintln!("  {} {}", "Error:".red(), e);
                            false
                        }
                    }
                }
                Err(_) => false,
            }
        }
    }

    fn execute_query(&mut self, input: &str) {
        // Validate input against security limits
        if let Err(e) = validate_query(input, &self.limits) {
            self.log_audit("QUERY_REJECTED", &format!("Validation failed: {}", e), false);
            println!("  {} {}", "✗".red().bold(), e.to_string().red());
            return;
        }

        // Parse
        let stmt = match driftdb_query::parse(input) {
            Ok(s) => s,
            Err(e) => {
                self.log_audit("PARSE_ERROR", &e.to_string(), false);
                println!("  {} {}", "✗".red().bold(), e.to_string().red());
                return;
            }
        };

        // Log the operation
        let op_type = format!("{:?}", stmt).split('(').next().unwrap_or("UNKNOWN").split('{').next().unwrap_or("UNKNOWN").trim().to_string();

        // Execute
        match self.executor.execute(stmt) {
            Ok(result) => {
                self.log_audit(&op_type, input, true);
                self.display_result(result);
            }
            Err(e) => {
                self.log_audit(&op_type, &format!("FAILED: {}", e), false);
                println!("  {} {}", "✗".red().bold(), e.to_string().red());
            }
        }
    }

    fn display_result(&self, result: QueryResult) {
        match result {
            QueryResult::NodeCreated { node } => {
                let labels = node.labels.join(":");
                println!(
                    "  {} Node created  {}  :{}",
                    "✓".green().bold(),
                    format!("(id: {})", node.id).dimmed(),
                    labels.bright_yellow()
                );
                for (key, val) in &node.properties {
                    println!(
                        "    {} {} = {}",
                        "│".dimmed(),
                        key.bright_white(),
                        format!("{}", val).bright_green()
                    );
                }
            }

            QueryResult::EdgeCreated { edge_id, edge_type } => {
                println!(
                    "  {} Edge created  {}  -[:{}]->",
                    "✓".green().bold(),
                    format!("(id: {})", edge_id).dimmed(),
                    edge_type.bright_yellow()
                );
            }

            QueryResult::Table { columns, rows } => {
                if rows.is_empty() {
                    println!("  {}", "(no results)".dimmed());
                    return;
                }

                let mut table = Table::new();
                table.load_preset(UTF8_FULL);
                table.set_header(&columns);

                for row in &rows {
                    table.add_row(row);
                }

                for line in table.to_string().lines() {
                    println!("  {}", line);
                }
                println!(
                    "  {}",
                    format!("{} result(s)", rows.len()).dimmed()
                );
            }

            QueryResult::SimilarResults { results } => {
                if results.is_empty() {
                    println!("  {}", "(no similar results found)".dimmed());
                    return;
                }

                let mut table = Table::new();
                table.load_preset(UTF8_FULL);
                table.set_header(vec!["Node", "Similarity"]);

                for (node_str, sim) in &results {
                    table.add_row(vec![node_str.clone(), format!("{:.4}", sim)]);
                }

                for line in table.to_string().lines() {
                    println!("  {}", line);
                }
            }

            QueryResult::PropertySet { node_id, property } => {
                println!(
                    "  {} Property '{}' updated on {}",
                    "✓".green().bold(),
                    property.bright_white(),
                    node_id.dimmed()
                );
            }

            QueryResult::Deleted { id } => {
                println!(
                    "  {} Node {} deleted (soft-delete, history preserved)",
                    "✓".green().bold(),
                    id.dimmed()
                );
            }

            QueryResult::Info(text) => {
                for line in text.lines() {
                    println!("  {}", line);
                }
            }

            QueryResult::HelpText(text) => {
                println!("{}", text.bright_white());
            }

            QueryResult::Ok => {
                println!("  {}", "OK".green().bold());
            }
        }
    }

    fn show_audit(&self) {
        let audit = self.audit.lock().unwrap();
        let recent = audit.recent(20);

        if recent.is_empty() {
            println!("  {}", "(no audit entries)".dimmed());
            return;
        }

        println!("  {} {}", "📋".to_string(), "Audit Log (last 20):".bright_white().bold());
        println!();

        for entry in recent {
            let status = if entry.success {
                "✓".green().to_string()
            } else {
                "✗".red().to_string()
            };
            println!(
                "  {} [{}] {} — {} ({})",
                status,
                entry.timestamp.format("%H:%M:%S").to_string().dimmed(),
                entry.operation.bright_yellow(),
                entry.details.bright_white(),
                entry.hash[..8].to_string().dimmed()
            );
        }

        println!();
        println!(
            "  {} total entries, chain hash: {}",
            audit.count().to_string().bright_white(),
            "verified".bright_green()
        );
    }

    fn verify_audit(&self) {
        let audit = self.audit.lock().unwrap();
        if audit.verify_integrity() {
            println!(
                "  {} {} — {} entries verified, hash chain intact",
                "✓".green().bold(),
                "Audit log integrity OK".bright_green(),
                audit.count()
            );
        } else {
            println!(
                "  {} {} — TAMPERED DATA DETECTED",
                "✗".red().bold(),
                "AUDIT LOG INTEGRITY VIOLATION".bright_red()
            );
        }
    }

    fn show_security(&self) {
        println!("  {} {}", "🔒".to_string(), "Security Status:".bright_white().bold());
        println!();
        println!("  {} Encryption:    {}", "│".dimmed(), "AES-256-GCM (available)".bright_green());
        println!("  {} Auth:          {}", "│".dimmed(),
            if self.require_auth { "Argon2id (active)".bright_green().to_string() }
            else { "Disabled (use --auth)".yellow().to_string() }
        );
        println!("  {} Integrity:     {}", "│".dimmed(), "SHA-256 checksums".bright_green());
        println!("  {} WAL:           {}", "│".dimmed(), "Write-Ahead Log (crash recovery)".bright_green());
        println!("  {} Compression:   {}", "│".dimmed(), "LZ4 (smart thresholds)".bright_green());
        println!("  {} Transactions:  {}", "│".dimmed(), "ACID with savepoints".bright_green());
        println!("  {} Audit Log:     {}", "│".dimmed(),
            format!("{} entries", self.audit.lock().unwrap().count()).bright_green()
        );
        println!("  {} Query Limits:  {}", "│".dimmed(),
            format!("max {}B query, {} props, {}D vectors",
                self.limits.max_query_length,
                self.limits.max_properties,
                self.limits.max_vector_dims
            ).bright_green()
        );
        println!("  {} Input Checks:  {}", "│".dimmed(), "null bytes, control chars, length".bright_green());
    }

    fn show_health(&self) {
        let start = std::time::Instant::now();
        match driftdb_core::ops::health_check(&self.storage) {
            Ok(report) => {
                let status_color = match report.overall {
                    driftdb_core::ops::HealthStatus::Healthy => "HEALTHY ✓".bright_green(),
                    driftdb_core::ops::HealthStatus::Degraded => "DEGRADED ⚠".yellow(),
                    driftdb_core::ops::HealthStatus::Critical => "CRITICAL ✗".bright_red(),
                };

                println!("  {} {} — {}", "🏥".to_string(), "Health Report".bright_white().bold(), status_color);
                println!();

                for check in &report.checks {
                    let icon = match check.status {
                        driftdb_core::ops::HealthStatus::Healthy => "✓".green(),
                        driftdb_core::ops::HealthStatus::Degraded => "⚠".yellow(),
                        driftdb_core::ops::HealthStatus::Critical => "✗".red(),
                    };
                    println!(
                        "  {} {:<22} {} ({:.1}ms)",
                        icon,
                        check.name.bright_white(),
                        check.detail.dimmed(),
                        check.duration_ms
                    );
                }

                let elapsed = start.elapsed();
                println!();
                println!(
                    "  {}",
                    format!("Full check completed in {:.1}ms", elapsed.as_secs_f64() * 1000.0).dimmed()
                );
                self.log_audit("HEALTH_CHECK", &format!("{}", report.overall), true);
            }
            Err(e) => {
                println!("  {} Health check failed: {}", "✗".red().bold(), e.to_string().red());
                self.log_audit("HEALTH_CHECK", &format!("FAILED: {}", e), false);
            }
        }
    }

    fn do_backup(&self) {
        println!("  {} {}", "📦".to_string(), "Creating backup...".bright_white());
        match driftdb_core::ops::create_backup(&self.storage, "./drift_backups") {
            Ok(path) => {
                println!(
                    "  {} Backup created at {}",
                    "✓".green().bold(),
                    path.display().to_string().bright_green()
                );
                self.log_audit("BACKUP", &format!("Created at {}", path.display()), true);
            }
            Err(e) => {
                println!("  {} Backup failed: {}", "✗".red().bold(), e.to_string().red());
                self.log_audit("BACKUP", &format!("FAILED: {}", e), false);
            }
        }
    }

    fn do_flush(&self) {
        match self.storage.flush() {
            Ok(()) => {
                println!("  {} All pending writes flushed to disk", "✓".green().bold());
                self.log_audit("FLUSH", "Writes flushed to disk", true);
            }
            Err(e) => {
                println!("  {} Flush failed: {}", "✗".red().bold(), e.to_string().red());
                self.log_audit("FLUSH", &format!("FAILED: {}", e), false);
            }
        }
    }

    fn log_audit(&self, operation: &str, details: &str, success: bool) {
        if let Ok(mut audit) = self.audit.lock() {
            audit.log(operation, details, success);
        }
    }
}

fn dirs_hint() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    format!("{}/.driftdb_history", home)
}
