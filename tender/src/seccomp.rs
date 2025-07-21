use anyhow::{Context, Result};
use libc::priority_t;
use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};

/// Essential syscalls for unikernel operation (Solo5-spt minimal set)
#[derive(Debug, Clone)]
pub struct AllowedSyscall {
    pub name: &'static str,
    pub number: ScmpSyscall,
    pub required: bool,
    pub description: &'static str,
}

/// Security policy configuration for unikernel execution
pub struct SecurityPolicy {
    allowed_syscalls: Vec<AllowedSyscall>,
    policy_name: String,
}

impl SecurityPolicy {
    /// Create minimal security policy based on solo5-spt
    pub fn minimal_unikernel_policy() -> Self {
        let syscalls = vec![
            AllowedSyscall {
                name: "write",
                number: ScmpSyscall::new("write"),
                required: true,
                description: "Console output and logging",
            },
            AllowedSyscall {
                name: "exit_group",
                number: ScmpSyscall::new("exit_group"),
                required: true,
                description: "Clean process termination",
            },
            AllowedSyscall {
                name: "clock_gettime",
                number: ScmpSyscall::new("clock_gettime"),
                required: true,
                description: "Timing and monotonic clock access",
            },
            // Optional syscall for enhanced functionality
            AllowedSyscall {
                name: "read",
                number: ScmpSyscall::new("read"),
                required: false,
                description: "Input operations (optional)",
            },
            AllowedSyscall {
                name: "ppoll",
                number: ScmpSyscall::new("ppoll"),
                required: false,
                description: "Event polling and yielidng (optional)",
            },
        ];

        SecurityPolicy {
            allowed_syscalls: syscalls,
            policy_name: "PolyKernel minimal".to_string(),
        }
    }

    /// Get policy statistics
    pub fn policy_stats(&self) -> (usize, usize, usize) {
        let required = self.allowed_syscalls.iter().filter(|s| s.required).count();
        let optional = self.allowed_syscalls.iter().filter(|s| !s.required).count();
        let total = self.allowed_syscalls.len();
        (required, optional, total)
    }

    /// Display security policy information
    pub fn display_policy(&self) {
        let (required, optional, total) = self.policy_stats();

        println!("\n🛡️  Security Policy: {}", self.policy_name);
        println!("   Required syscalls: {}", required);
        println!("   Optional syscalls: {}", optional);
        println!("   Total allowed: {}", total);
        println!(
            "   Attack surface reduction: ~{}%",
            100 - (total * 100 / 300)
        );

        println!("\n📋 Allowed System Calls:");
        for syscall in &self.allowed_syscalls {
            let status = if syscall.required {
                "REQUIRED"
            } else {
                "OPTIONAL"
            };
            println!("  {} {}: {}", status, syscall.name, syscall.description)
        }
    }
}

pub struct SeccompFilter {
    policy: SecurityPolicy,
    filter_context: Option<ScmpFilterContext>,
    filter_installed: bool,
}

impl SeccompFilter {
    /// Create new seccomp filter with minimal policy
    pub fn new() -> Result<Self> {
        Ok(SeccompFilter {
            policy: SecurityPolicy::minimal_unikernel_policy(),
            filter_context: None,
            filter_installed: false,
        })
    }

    /// Prepare seccomp filter
    pub fn setup_filter(&mut self) -> Result<()> {
        println!("  Setting up seccomp-BPF filter...");

        // Create filter context with default KILL action
        let mut ctx = ScmpFilterContext::new(ScmpAction::KillProcess)
            .context("Failed to create seccomp filter context")?;

        // Add allowed syscalls to whitelist
        for syscall in &self.policy.allowed_syscalls {
            ctx.add_rule(ScmpAction::Allow, syscall.number)
                .with_context(|| format!("Failed to add rule for syscall: {}", syscall.name))?;

            println!("  Added {} to whitelist", syscall.name);
        }

        self.filter_context = Some(ctx);
        println!(
            "  Seccomp filter prepared with {} allowed syscalls",
            self.policy.allowed_syscalls.len()
        );

        Ok(())
    }

    /// Install seccomp filter
    pub fn install_filter(&mut self) -> Result<()> {
        if self.filter_installed {
            return Ok(());
        }

        let ctx = self.filter_context.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Filter not setup - call setup_filter"))?;

        println!("  Installing seccomp-BPF filter...");

        // Load the filter into the kernel
        ctx.load().context("Failed to load seccomp filter into kernel")?;

        self.filter_installed = true;
        println!("  Hardware-enforced security activated");
        println!("  Guest syscalls now restricted to whitelist");

        Ok(())
    }

    pub fn validate_security(&self) -> Result<()> {
        if !self.filter_installed {
            anyhow::bail!("Securtiy policy not installed - guest execution would be unsafe");
        }

        println!("\n🔍 Security Validation:");
        println!("   ✅ Seccomp filter installed");
        println!("   ✅ Syscall whitelist active");
        println!("   ✅ Attack surface minimized");
        println!("   🛡️  Guest ready for secure execution");

        Ok(())
    }

    pub fn display_policy(&self) {
        self.policy.display_policy();
    }


    pub fn test_security_setup(&self) -> Result<()> {
        println!("\n🧪 Security Setup Test:");

        if self.filter_context.is_some() {
            println!("   ✅ Filter context created");
        } else {
            println!("   ❌ Filter context not created");
        }

        if self.filter_installed {
            println!("   ✅ Filter installed and active");
        } else {
            println!("   ⚠️  Filter prepared but not yet installed");
        }

        let (required, optional, total) = self.policy.policy_stats();
        println!("   📊 Policy: {} required + {} optional = {} total syscalls",
                 required, optional, total);

        Ok(())
    }
}

pub fn setup_security_framework() -> Result<SeccompFilter> {
    println!("Initialising security framework...");

    let mut filter = SeccompFilter::new()
        .context("Failed to create seccomp filter")?;

    filter.display_policy();

    filter.setup_filter()
        .context("Failed to setup seccomp filter")?;

    println!("\n Filter prepared but not yet installed");
    println!("  Installation will occur before guest execution");

    Ok(filter)
}

pub fn test_security_framework() -> Result<()> {
    println!("  Testing security framework");

    let mut filter = setup_security_framework()
        .context("Failed to setup security framework")?;

    filter.test_security_setup().
        context("Security setup failed")?;

    println!("  Securty framework testing completed!");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_creation() {
        let policy = SecurityPolicy::minimal_unikernel_policy();
        let (required, optional, total) = policy.policy_stats();

        assert!(required >= 3);
        assert!(total <= 7);
        assert_eq!(total, required + optional);

    }

    #[test]
    fn test_filter_creation () {
        let filter = SeccompFilter::new();
        assert!(filter.is_ok());

        let filter = filter.unwrap();
        assert!(!filter.filter_installed);
        assert!(filter.filter_context.is_none());
    }
}