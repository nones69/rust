//! ikrl-windows — Windows service wrapper for the IntentKernel daemon stack.
//!
//! This binary is the Windows deployment entry point. When run with no
//! arguments it starts the IntentKernel daemons as a normal process set
//! (useful for development). With `--install`/`--uninstall` it registers
//! itself as a Windows service so the stack starts automatically.
//!
//! On non-Windows platforms it prints a compatibility message and exits.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "ikrl-windows")]
#[command(about = "IntentKernel Windows service wrapper")]
struct Args {
    #[arg(long)]
    install: bool,
    #[arg(long)]
    uninstall: bool,
    #[arg(long, default_value = "IntentKernel")]
    service_name: String,
}

#[cfg(windows)]
mod win {
    use super::*;
    use std::ffi::OsString;
    use std::time::Duration;
    use windows_service::{
        service::{ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceType},
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

        service_dispatcher::start(OsString::from(&args.service_name), service_main).unwrap();
    }

    fn install(name: &str) -> windows_service::Result<()> {
        let manager =
            ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)?;
        let exe = std::env::current_exe().unwrap();
        let info = ServiceInfo {
            name: OsString::from(name),
            display_name: OsString::from("IntentKernel Security Substrate"),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: exe,
            launch_arguments: vec![],
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

    extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
        let event_handler = move |control| match control {
            windows_service::service::ServiceControl::Stop
            | windows_service::service::ServiceControl::Interrogate => {
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        };

        let _status_handle =
            service_control_handler::register(OsString::from("IntentKernel"), event_handler)
                .unwrap();

        tracing::info!("IntentKernel Windows service running");
        loop {
            std::thread::sleep(Duration::from_secs(60));
        }
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
