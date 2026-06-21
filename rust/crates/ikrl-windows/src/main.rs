//! ikrl-windows — Windows service registration stub for the IntentKernel daemon stack.
//!
//! Current state:
//! - `--install` / `--uninstall` register or remove a Windows service entry.
//! - Running under the Service Control Manager only registers a control handler
//!   and then idles.
//! - It does **not** yet launch or supervise `ikrl-init` or the daemon stack.
//!
//! For development and current Windows usage, launch `ikrl-init.exe` directly.
//! On non-Windows platforms this binary prints a compatibility message and exits.

use clap::Parser;

const SERVICE_DISPLAY_NAME: &str = "IntentKernel Security Substrate";

#[cfg(windows)]
static SERVICE_NAME: std::sync::OnceLock<String> = std::sync::OnceLock::new();

#[derive(Parser, Debug)]
#[command(name = "ikrl-windows")]
#[command(about = "IntentKernel Windows service wrapper")]
struct Args {
    #[arg(long)]
    install: bool,
    #[arg(long)]
    uninstall: bool,
    #[arg(long, hide = true)]
    run_service: bool,
    #[arg(long, default_value = "IntentKernel")]
    service_name: String,
}

#[cfg(windows)]
mod win {
    use super::*;
    use std::ffi::OsString;
    use std::sync::mpsc;
    use std::time::Duration;
    use windows_service::{
        service::{
            ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
            ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    pub fn run(args: Args) {
        if args.install {
            install(&args.service_name).unwrap();
            return;
        }
        if args.uninstall {
            uninstall(&args.service_name).unwrap();
            return;
        }
        if args.run_service {
            run_service(&args.service_name);
            return;
        }

        eprintln!(
            "ikrl-windows currently installs a Windows service entry only; launch ikrl-init.exe for the actual daemon stack"
        );
        std::process::exit(2);
    }

    fn install(name: &str) -> windows_service::Result<()> {
        let manager =
            ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)?;
        let exe = std::env::current_exe().unwrap();
        let info = ServiceInfo {
            name: OsString::from(name),
            display_name: OsString::from(SERVICE_DISPLAY_NAME),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: exe,
            launch_arguments: vec![
                OsString::from("--run-service"),
                OsString::from("--service-name"),
                OsString::from(name),
            ],
            dependencies: vec![],
            account_name: None,
            account_password: None,
        };
        let _service = manager.create_service(&info, ServiceAccess::CHANGE_CONFIG)?;
        println!("Service '{}' installed.", name);
        Ok(())
    }

    fn uninstall(name: &str) -> windows_service::Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let service = manager.open_service(OsString::from(name), ServiceAccess::DELETE)?;
        service.delete()?;
        println!("Service '{}' uninstalled.", name);
        Ok(())
    }

    fn run_service(service_name: &str) {
        let _ = SERVICE_NAME.set(service_name.to_string());
        service_dispatcher::start(service_name, service_main).unwrap();
    }

    extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let event_handler = move |control| match control {
            ServiceControl::Stop => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        };

        let service_name = SERVICE_NAME
            .get()
            .map(String::as_str)
            .unwrap_or("IntentKernel");
        let status_handle = service_control_handler::register(service_name, event_handler).unwrap();

        status_handle
            .set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::Running,
                controls_accepted: ServiceControlAccept::STOP,
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            })
            .unwrap();

        tracing::warn!(
            "IntentKernel Windows service stub is running; it does not yet launch ikrl-init or supervise daemons"
        );

        let _ = shutdown_rx.recv();

        status_handle
            .set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::Stopped,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            })
            .unwrap();
    }
}

#[cfg(windows)]
fn main() {
    tracing_subscriber::fmt::init();
    win::run(Args::parse());
}

#[cfg(not(windows))]
fn main() {
    let _ = Args::parse();
    eprintln!("ikrl-windows is only supported on Windows; use ikrl-init on this platform");
    std::process::exit(1);
}
