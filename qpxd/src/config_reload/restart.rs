use super::{ConfigReloadHandler, emit_config_reload_audit};
use crate::server::ProxyTasks;
use crate::startup::{log_runtime_ready, validate_runtime_state};
use crate::{runtime, tcp_bindings, udp_bindings};
use qpx_core::config::Config as ProxyConfig;
use tracing::{info, warn};

impl ConfigReloadHandler {
    pub(super) async fn apply_restart_reload(
        &self,
        current: &mut ProxyConfig,
        runtime: &mut runtime::Runtime,
        proxy: &mut ProxyTasks,
        new_config: ProxyConfig,
    ) -> bool {
        let new_runtime = match runtime::Runtime::with_http_module_registry(
            new_config.clone(),
            self.http_module_registry.clone(),
        ) {
            Ok(runtime) => runtime,
            Err(err) => {
                warn!(error = ?err, "config reload failed");
                emit_config_reload_audit(
                    "failed",
                    None,
                    None,
                    self.configs_display.as_str(),
                    Some(&err),
                );
                return false;
            }
        };

        let next_state = new_runtime.state();
        if let Err(err) = validate_runtime_state(next_state.as_ref()) {
            warn!(error = ?err, "config reload reverse compile failed");
            emit_config_reload_audit(
                "failed",
                None,
                Some("reverse_compile_error"),
                self.configs_display.as_str(),
                Some(&err),
            );
            return false;
        }

        let tcp_bindings = match tcp_bindings::TcpBindings::bind_for_hot_reload(
            &new_config,
            current,
            proxy.tcp_bindings(),
        ) {
            Ok(bindings) => bindings,
            Err(err) => {
                warn!(error = ?err, "config reload bind failed");
                emit_config_reload_audit(
                    "failed",
                    None,
                    Some("tcp_bind_error"),
                    self.configs_display.as_str(),
                    Some(&err),
                );
                return false;
            }
        };
        let udp_bindings = match udp_bindings::UdpBindings::bind_for_hot_reload(
            &new_config,
            current,
            proxy.udp_bindings(),
        ) {
            Ok(bindings) => bindings,
            Err(err) => {
                warn!(error = ?err, "config reload udp bind failed");
                emit_config_reload_audit(
                    "failed",
                    None,
                    Some("udp_bind_error"),
                    self.configs_display.as_str(),
                    Some(&err),
                );
                return false;
            }
        };

        // Pool limits are owned per-runtime: `new_runtime`'s `PoolRegistry` already has
        // the new config's limits applied at build time, so no global toggle is needed.
        let new_proxy = match ProxyTasks::start(
            &new_config,
            new_runtime.clone(),
            tcp_bindings,
            udp_bindings,
            None,
            #[cfg(feature = "http3")]
            None,
        ) {
            Ok(tasks) => tasks,
            Err(err) => {
                warn!(error = ?err, "config reload start failed; keeping old proxy tasks");
                emit_config_reload_audit(
                    "failed",
                    None,
                    Some("start_error"),
                    self.configs_display.as_str(),
                    Some(&err),
                );
                return false;
            }
        };

        let old_proxy = std::mem::replace(proxy, new_proxy);
        if let Err(err) = old_proxy.stop_all().await {
            warn!(error = ?err, "old proxy tasks failed while draining after reload");
        }
        // `new_runtime` owns freshly built connection pools, so there is nothing to flush.
        log_runtime_ready(&new_runtime);
        info!("config reloaded; listener/reverse server set restarted");
        emit_config_reload_audit(
            "applied",
            Some("restart"),
            None,
            self.configs_display.as_str(),
            None,
        );
        *current = new_config;
        *runtime = new_runtime;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::modules::default_http_module_registry;
    use std::io::{self, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::util::SubscriberInitExt;

    #[derive(Default)]
    struct AuditOutput(Mutex<Vec<u8>>);

    impl Write for &AuditOutput {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().write(bytes)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[cfg(windows)]
    fn bind_exclusive_listener() -> io::Result<TcpListener> {
        use socket2::{Domain, SockAddr, Socket, Type};
        use std::net::SocketAddr;
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{
            SO_EXCLUSIVEADDRUSE, SOL_SOCKET, WSAGetLastError, setsockopt,
        };

        let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
        // Windows SO_REUSEADDR can otherwise let the reload bind an occupied port.
        let exclusive = 1_i32;
        // SAFETY: The socket is live and the pointer is valid for the option's i32 size.
        if unsafe {
            setsockopt(
                socket.as_raw_socket() as _,
                SOL_SOCKET,
                SO_EXCLUSIVEADDRUSE,
                (&raw const exclusive).cast(),
                size_of::<i32>() as i32,
            )
        } != 0
        {
            // SAFETY: WSAGetLastError reads the calling thread's error and takes no arguments.
            let error = unsafe { WSAGetLastError() };
            return Err(io::Error::from_raw_os_error(error));
        }
        socket.bind(&SockAddr::from(SocketAddr::from(([127, 0, 0, 1], 0))))?;
        socket.listen(1)?;
        Ok(socket.into())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn config_reload_restart_reports_tcp_bind_failure() {
        let mut current: ProxyConfig = serde_yaml::from_str(
            "
            runtime: { acceptor_tasks_per_listener: 1 }
            edges:
              - kind: forward
                name: test
                listen: 127.0.0.1:0
                default_action: { type: direct }
            ",
        )
        .expect("parse current config");
        let mut runtime = runtime::Runtime::new(current.clone()).expect("build current runtime");
        let mut proxy = ProxyTasks::start(
            &current,
            runtime.clone(),
            tcp_bindings::TcpBindings::bind(&current).expect("bind current TCP listeners"),
            udp_bindings::UdpBindings::bind(&current).expect("bind current UDP sockets"),
            None,
            #[cfg(feature = "http3")]
            None,
        )
        .expect("start current proxy");
        let old_task = proxy.tcp_task.id();

        #[cfg(not(windows))]
        let occupied = TcpListener::bind("127.0.0.1:0").expect("hold the new listen address");
        #[cfg(windows)]
        let occupied = bind_exclusive_listener().expect("hold the new listen address");
        let mut next = current.clone();
        next.ingress_edges_mut().next().unwrap().listen =
            occupied.local_addr().unwrap().to_string();
        let handler =
            ConfigReloadHandler::new(vec!["test.yaml".into()], default_http_module_registry());
        let output = Arc::new(AuditOutput::default());
        let applied = {
            let _guard = tracing_subscriber::fmt()
                .json()
                .without_time()
                .with_max_level(tracing::Level::WARN)
                .with_writer(output.clone())
                .set_default();
            handler
                .apply_restart_reload(&mut current, &mut runtime, &mut proxy, next)
                .await
        };
        let retained_task = proxy.tcp_task.id();
        proxy.stop_all().await.expect("stop proxy");

        assert!(!applied, "reload must reject the occupied listener");
        assert_eq!(retained_task, old_task, "reload replaced the old proxy");
        let output = output.0.lock().unwrap();
        let output = std::str::from_utf8(&output).expect("UTF-8 log output");
        assert!(
            output.lines().any(|line| {
                let entry: serde_json::Value = serde_json::from_str(line).expect("JSON log entry");
                entry["target"] == "audit_log"
                    && entry["fields"]["event"] == "config_reload"
                    && entry["fields"]["outcome"] == "failed"
                    && entry["fields"]["reason"] == "tcp_bind_error"
            }),
            "missing TCP bind failure audit event: {output}"
        );
    }
}
