use bcc::core::BPF;
use bcc::BccError;
use clap::{App, Arg};

use core::sync::atomic::{AtomicBool, Ordering};
use std::collections::HashMap;
use std::sync::Arc;
use std::{cmp, mem, ptr, thread, time};

// A simple tool for reporting on time spent in hardirq handlers
//
// Based on: https://github.com/iovisor/bcc/blob/master/tools/hardirqs.py

#[repr(C)]
struct irq_key_t {
    name: [u8; 32],
    slot: u64,
}

fn do_main(runnable: Arc<AtomicBool>) -> Result<(), BccError> {
    let matches = App::new("hardirqs")
        .about("Summarize hard IRQ event time")
        .arg(
            Arg::with_name("interval")
                .long("interval")
                .value_name("Seconds")
                .help("Integration window duration and period for stats output")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("windows")
                .long("windows")
                .value_name("Count")
                .help("The number of intervals before exit")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("nanoseconds")
                .long("nano")
                .short("N")
                .help("Display the timestamps in nanoseconds")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("distribution")
                .long("dist")
                .short("d")
                .help("Show the distribution")
                .takes_value(false),
        )
        .get_matches();

    let interval: usize = matches
        .value_of("interval")
        .unwrap_or("1")
        .parse()
        .expect("Invalid number of interval");

    let windows: Option<usize> = matches
        .value_of("windows")
        .map(|v| v.parse().expect("Invalud argument for windows"));

    let (factor, unit) = if matches.is_present("nanoseconds") {
        (1, "ns")
    } else {
        (1000, "us")
    };

    let code = include_str!("bpf.c");
    let code = if matches.is_present("distribution") {
        code.replace(
            "##STORE##",
            &format!(
                "irq_key_t key = {{.slot = bpf_log2l(delta / {factor})}};
                bpf_probe_read_kernel(&key.name, sizeof(key.name), name);
                dist.increment(key);",
                factor = factor
            ),
        )
    } else {
        code.replace(
            "##STORE##",
            "irq_key_t key = {.slot = 0 /* ignore */};
            bpf_probe_read(&key.name, sizeof(key.name), name);
            dist.increment(key, delta);",
        )
    };

    let mut bpf = BPF::new(&code)?;

    let hardirq_entry = bpf.load_kprobe("hardirq_entry")?;
    let hardirq_exit = bpf.load_kprobe("hardirq_exit")?;

    bpf.attach_kprobe("handle_irq_event_percpu", hardirq_entry)?;
    bpf.attach_kretprobe("handle_irq_event_percpu", hardirq_exit)?;

    let mut table = bpf.table("dist");
    let mut window = 0;

    while runnable.load(Ordering::SeqCst) {
        thread::sleep(time::Duration::new(interval as u64, 0));

        if matches.is_present("distribution") {
            print_distribution(&mut table, unit);
        } else {
            print_time(&mut table, factor, unit)
        }

        if let Some(windows) = windows {
            window += 1;
            if window >= windows {
                return Ok(());
            }
        }
    }
    Ok(())
}

fn print_distribution(table: &mut bcc::table::Table, unit: &str) {
    println!("\n=====");
    for (hardirq_name, value) in map_from_table(table) {
        let mut idx_max = 0u64;
        let mut cnt_max = 0u64;

        for (slot, cnt) in &value {
            idx_max = cmp::max(*slot, idx_max);
            cnt_max = cmp::max(*cnt, cnt_max);
        }

        if idx_max < 1 || cnt_max == 0 {
            continue;
        }

        println!("\n{}\n   time({}) {:>-19}", hardirq_name, unit, "count");
        for i in 1..(idx_max + 1) {
            let mut low = (1 << i) >> 1;
            let high = (1 << i) - 1;

            if low == high {
                low -= 1;
            }

            let val = value.get(&i).unwrap_or(&0);

            println!(
                "{:>10} : {:<-10} : {:<-8} |{:<-40}|",
                low,
                high,
                val,
                format!("{:*<1$}", "", (val * 40 / cnt_max) as usize)
            );
        }
    }
}

fn print_time(table: &mut bcc::table::Table, factor: u64, unit: &str) {
    println!("\n{:<-16} {:<-11}", "HARDIRQ", unit);
    for entry in table.iter() {
        let data = parse_struct(&entry.key);
        let value = entry.value;

        let mut v = [0_u8; 8];
        for i in 0..8 {
            v[i] = *value.get(i).unwrap_or(&0);
        }
        let time: u64 = unsafe { mem::transmute(v) };
        let name = get_string(&data.name);

        if time > 0 {
            println!("{:<-16} {:<-11}", name, time / factor);
        }

        let mut key = [0; 40];
        key.copy_from_slice(&entry.key);
        let _ = table.set(&mut key, &mut [0_u8; 8]);
    }
}

fn map_from_table(table: &mut bcc::table::Table) -> HashMap<String, HashMap<u64, u64>> {
    let mut current: HashMap<String, HashMap<u64, u64>> = HashMap::new();

    for mut entry in table.iter() {
        let key = parse_struct(&entry.key);
        let name = get_string(&key.name);

        if !current.contains_key(&name) {
            current.insert(name, HashMap::new());
        }

        let mut value = [0; 8];
        if value.len() != entry.value.len() {
            continue;
        }
        value.copy_from_slice(&entry.value);
        let value = u64::from_ne_bytes(value);

        let map = current.get_mut(&get_string(&key.name));

        map.unwrap().insert(key.slot, value);

        // Clear the table to reset counter
        let _ = table.delete(&mut entry.key);
    }

    current
}

fn parse_struct(x: &[u8]) -> irq_key_t {
    unsafe { ptr::read(x.as_ptr() as *const irq_key_t) }
}

fn get_string(x: &[u8]) -> String {
    match x.iter().position(|&r| r == 0) {
        Some(zero_pos) => String::from_utf8_lossy(&x[0..zero_pos]).to_string(),
        None => String::from_utf8_lossy(x).to_string(),
    }
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
            std::process::exit(1);
        }
        _ => {}
    }
}
