use bcc::core::BPF;
use clap::{App, Arg};
use core::sync::atomic::{AtomicBool, Ordering};
use failure::Error;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::{ptr, str};

/*
 * Define the struct the BPF code writes in Rust
 * This must match the struct in `opensnoop.c` exactly.
 * The important thing to understand about the code in `opensnoop.c` is that it creates structs of
 * type `data_t` and pushes them into a buffer where our Rust code can read them.
 */
#[repr(C)]
struct ipv4_data_t {
    ts_us: u64,
    pid: u32,
    uid: u32,
    saddr: u32,
    daddr: u32,
    ip: u64,
    dport: u16,
    task: [u8; 16], // TASK_COMM_LEN
}

#[repr(C)]
struct ipv6_data_t {
    ts_us: u64,
    pid: u32,
    uid: u32,
    saddr: u128,
    daddr: u128,
    ip: u64,
    dport: u16,
    task: [u8; 16], // TASK_COMM_LEN
}

trait IpDataParse<Output> {
    fn parse_data_t_struct(x: &[u8]) -> Output;
}

impl IpDataParse<ipv4_data_t> for ipv4_data_t {
    fn parse_data_t_struct(x: &[u8]) -> ipv4_data_t {
        unsafe { ptr::read(x.as_ptr() as *const ipv4_data_t) }
    }
}

impl IpDataParse<ipv6_data_t> for ipv6_data_t {
    fn parse_data_t_struct(x: &[u8]) -> ipv6_data_t {
        unsafe { ptr::read(x.as_ptr() as *const ipv6_data_t) }
    }
}

fn perf_ipv4_data_t_callback() -> Box<dyn FnMut(&[u8]) + Send> {
    Box::new(|x| {
        // This callback
        let data: ipv4_data_t = ipv4_data_t::parse_data_t_struct(x);
        if let Ok(task) = str::from_utf8(&data.task) {
            println!(
                "{: <6} {: <6} {: <16} {: <16} {: <16} {: <16} {: <4}", // "UID", "PID", "COMM", "IP", "SADDR", "DADDR", "DPORT"
                data.uid,
                data.pid,
                task.trim_end_matches('\0'),
                data.ip,
                Ipv4Addr::from(htonl(data.saddr)).to_string(),
                Ipv4Addr::from(htonl(data.daddr)).to_string(),
                data.dport
            );
        }
    })
}

fn perf_ipv6_data_t_callback() -> Box<dyn FnMut(&[u8]) + Send> {
    Box::new(|x| {
        // This callback
        let data: ipv6_data_t = ipv6_data_t::parse_data_t_struct(x);
        // .swap_bytes() always swap bytes, .to_be_bytes() swap if host is le, .to_le_bytes() swaps if host is be
        let saddr: u128 = u128::from_le_bytes(data.saddr.to_be_bytes());
        let daddr: u128 = u128::from_le_bytes(data.daddr.to_be_bytes());
        if let Ok(task) = str::from_utf8(&data.task) {
            println!(
                "{: <6} {: <6} {: <16} {: <16} {: <16} {: <16} {: <4}", // "UID", "PID", "COMM", "IP", "SADDR", "DADDR", "DPORT"
                data.uid,
                data.pid,
                task.trim_end_matches('\0'),
                data.ip,
                Ipv6Addr::from(saddr).to_string(),
                Ipv6Addr::from(daddr).to_string(),
                data.dport
            );
        }
    })
}

fn ntohs(u: u16) -> u16 {
    u16::from_be(u)
}
fn htonl(u: u32) -> u32 {
    u.to_be()
}

fn do_main(runnable: Arc<AtomicBool>) -> Result<(), Error> {
    let mut bpf_text: String = include_str!("bpf.c").to_string();
    let matches = App::new("tcpconnect")
        .about("Trace TCP connects")
        .long_about(
            "examples:
./tcpconnect           # trace all TCP connect()s
./tcpconnect -p 181    # only trace PID 181
./tcpconnect -P 80     # only trace port 80
./tcpconnect -P 22 8080  # only trace port 22 and 8080
./tcpconnect -u 1000   # only trace UID 1000",
        )
        .arg(
            Arg::with_name("uid")
                .short("u")
                .long("uid")
                .help("trace this UID only, e.g. -u 2322")
                .value_name("UID")
                .number_of_values(1)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("pid")
                .short("p")
                .long("pid")
                .help("trace this PID only, e.g. -p 343")
                .value_name("PID")
                .number_of_values(1)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("port")
                .short("P")
                .long("port")
                .help("destination ports to trace, e.g. -P 22 80 443")
                .value_name("PORT")
                .min_values(1)
                .required(false)
                .takes_value(true),
        )
        .get_matches();
    // handle pids
    if let Some(p) = matches.value_of("pid") {
        // trace pid
        let pid = p
            .parse::<u32>()
            .expect("pid should be a non-negative integer");
        bpf_text = {
            let pid_format = format!("if (pid != {}) {{ return 0; }}", pid);
            bpf_text.replace("FILTER_PID", pid_format.as_str())
        };
    }
    // handle ports
    if let Some(port_listings) = matches.values_of("port") {
        let mut ports_conditions: Vec<String> = Vec::new();
        for port in port_listings {
            let port_u16 = port.parse::<u16>().expect("port number between 1-65535");
            let port_ntohs = ntohs(port_u16);
            let port_condition = format!("dport != {}", port_ntohs);
            ports_conditions.push(port_condition);
        }
        bpf_text = bpf_text.replace(
            "FILTER_PORT",
            format!(
                "if ({}) {{ currsock.delete(&pid); return 0; }}",
                ports_conditions.join(" && ")
            )
            .as_str(),
        );
    }
    // handle uid
    if let Some(u) = matches.value_of("uid") {
        // trace uuid
        let uuid = u
            .parse::<u32>()
            .expect("uuid value should be an non-negative integer integer");
        bpf_text = {
            let uuid_set = format!("if (uid != {}) {{ return 0; }}", uuid);
            bpf_text.replace("FILTER_UID", uuid_set.as_str())
        };
    }
    // replace remaining unset template flags, if any
    bpf_text = bpf_text.replace("FILTER_PID", "");
    bpf_text = bpf_text.replace("FILTER_PORT", "");
    bpf_text = bpf_text.replace("FILTER_UID", "");

    // compile the above BPF code!
    let mut module = BPF::new(bpf_text.as_str())?;
    // load + attach tracepoints!
    let trace_connect_v4_entry = module.load_kprobe("trace_connect_entry")?;
    let trace_connect_v6_entry = module.load_kprobe("trace_connect_entry")?;
    let trace_connect_v4_return = module.load_kprobe("trace_connect_v4_return")?;
    let trace_connect_v6_return = module.load_kprobe("trace_connect_v6_return")?;
    module.attach_kprobe("tcp_v4_connect", trace_connect_v4_entry)?;
    module.attach_kprobe("tcp_v6_connect", trace_connect_v6_entry)?;
    module.attach_kretprobe("tcp_v4_connect", trace_connect_v4_return)?;
    module.attach_kretprobe("tcp_v6_connect", trace_connect_v6_return)?;

    println!("Tracing connect ... Hit Ctrl-C to end");
    let ipv4_table = module.table("ipv4_events");
    let ipv6_table = module.table("ipv6_events");
    let _ipv4_perf_map = module.init_perf_map(ipv4_table, perf_ipv4_data_t_callback)?;
    let _ipv6_perf_map = module.init_perf_map(ipv6_table, perf_ipv6_data_t_callback)?;
    // print a header
    println!(
        "{: <6} {: <6} {: <16} {: <16} {: <16} {: <16} {: <4}",
        "UID", "PID", "COMM", "IP", "SADDR", "DADDR", "DPORT"
    );

    while runnable.load(Ordering::SeqCst) {
        module.perf_map_poll(200);
    }
    Ok(())
}

fn main() {
    let runnable = Arc::new(AtomicBool::new(true));
    let r = runnable.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Failed to set handler for SIGINT / SIGTERM");

    match do_main(runnable) {
        Err(x) => {
            eprintln!("Error: {}", x);
            eprintln!("{}", x.backtrace());
            std::process::exit(1);
        }
        _ => {}
    }
}
