extern crate argparse;
extern crate pcap;

use argparse::{ArgumentParser, Store, StoreTrue};
use pcap::{Capture, Device};
use std::time::{SystemTime, UNIX_EPOCH};

static mut DEBUG: bool = false;

struct Burst {
    size: u32,
    timestamp: u128,
    d_time: u128
}

fn get_requested_device<'a> (dev_name : &str, requested_device : &'a mut Device, vec_devices : &'a Vec<Device>) {
    for device in vec_devices {
        if &*device.name == dev_name {
                requested_device.name = device.name.clone();
                requested_device.desc = device.desc.clone();
        };
    };
}

fn main() {

    let mut requested_device : Device = Device::lookup().unwrap();

    let mut print_devices : bool = false;
    let mut dev_name : String = "any".to_string();
    {
        let mut argparse = ArgumentParser::new();
        argparse.refer(&mut dev_name)
            .add_option(&["-d", "--device"], Store,
            "Select Device");
        unsafe { argparse.refer(&mut DEBUG)
            .add_option(&["-b", "--debug"], StoreTrue,
            "Debug Mode"); }

        argparse.parse_args_or_exit();
    }

    let devices = Device::list();
    match devices {
        Ok(vec_devices) => {
            get_requested_device(&dev_name, &mut requested_device, &vec_devices);
        }
        Err(_) => {
            println!("No devices found...");
            std::process::exit(1);
        },
    }

    let mut cap = Capture::from_device(requested_device)
                    .unwrap()
                    .open()
                    .unwrap();
    


    unsafe{if DEBUG {println!("debug: Started capture on: {:?}", dev_name)}};

    let mut last = SystemTime::now();
    let trace_start = SystemTime::now();

    let mut bursts : Vec<Burst> = Vec::new();
    let mut burst_size = 0;
    let mut bursts_captured = 0;
    let mut burst_packets = 1;
    let mut burst_diffs = 0;

    while let Ok(packet) = cap.next() {
        if packet.data[0x26] == 0x00 && packet.data[0x27] == 0x16 {

            let curr = SystemTime::now();

            let t_diff = curr.duration_since(UNIX_EPOCH).expect("failed").as_millis() - last.duration_since(UNIX_EPOCH).expect("failed").as_millis();

            let mut threshold = 4000;
            if bursts.len() > 1 {
                threshold = 10 * bursts[bursts.len() - 1].d_time;
            }

            if t_diff > threshold {
                let b = Burst {
                    size: burst_size,
                    timestamp: curr.duration_since(UNIX_EPOCH).expect("failed").as_millis(),
                    d_time: burst_diffs / burst_packets
                };

                bursts_captured += 1;
                burst_size = 0;
                burst_packets = 0;
                burst_diffs = 0;

                if bursts_captured != 1 {bursts.push(b)};
            }

            burst_packets += 1;
            burst_diffs += t_diff;
            burst_size += u32::from(packet.data[0x30]);

            last = SystemTime::now();
        }
    }

    for b in bursts {
        println!("Burst [Size: {:?}, Timestamp: {:?}, Diff: {:?}]", b.size, b.timestamp, b.d_time);
    }
    println!("Found {:?} rounds through bursts", bursts_captured);
}
