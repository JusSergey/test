#![no_std]
#![no_main]

use aya_bpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_bpf::helpers::{bpf_probe_read, bpf_probe_read_kernel};
use aya_log_ebpf::info;
use aya_log_ebpf::macro_support::DisplayHint::Default;
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{IpProto, Ipv4Hdr};
use network_types::tcp::TcpHdr;

#[xdp]
pub fn filter(ctx: XdpContext) -> u32 {
    match unsafe { xdp_firewall(&ctx) } {
        Ok(val) => val,
        _ => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: &mut usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();
    if start + *offset + len > end {
        return Err(());
    }

    let out = Ok((start + *offset) as *const T);
    *offset += len;
    out
}

// #[inline(always)]
// fn read_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
//     let start = ctx.data();
//     let end = ctx.data_end();
//     let len = core::mem::size_of::<T>();
//     if start + offset + len > end {
//         return Err(());
//     }
//
//     Ok((start + offset) as *const T)
// }

unsafe fn xdp_firewall(ctx: &XdpContext) -> Result<u32, ()> {
    let start = ctx.data();
    let end = ctx.data_end();

    let mut packed_offset = 0;
    let ehdr = ptr_at::<EthHdr>(ctx, &mut packed_offset)?;
    match (*ehdr).ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }
    let ipv4hdr = ptr_at::<Ipv4Hdr>(ctx, &mut packed_offset)?;
    let src_addr = u32::from_be((*ipv4hdr).src_addr);
    match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcp_header_start = packed_offset;
            let tcphdr = ptr_at::<TcpHdr>(ctx, &mut packed_offset)?;
            let (p1, p2) = (
                u16::from_be((*tcphdr).source),
                u16::from_be((*tcphdr).dest)
            );
            if p1 != 1235 {
                return Ok(xdp_action::XDP_PASS)
            }
            // let total = u16::from_be((*ipv4hdr).tot_len);

            let doff = ((*tcphdr).doff()) * 4;
            // info!(ctx, "Headers: {} + {} + {} = {}", EthHdr::LEN, Ipv4Hdr::LEN, TcpHdr::LEN, EthHdr::LEN + Ipv4Hdr::LEN + TcpHdr::LEN);
            // info!(ctx, "Data size: {}", end-start);
            // info!(ctx, "Total data: {}", total);
            // info!(ctx, "dof2f: {} {}", doff as usize, packed_offset);
            // info!(ctx, "data offset: {}", tcp_header_start + doff as usize);


            let range = tcp_header_start + doff as usize..(end-start);

            if range.start != 66 {
                return Ok(xdp_action::XDP_PASS)
            }

            let mut i = range.start;
            let mut c = 0;

            while i < range.end-1 {
                let ch = (ctx.data() + i as usize) as *const u8;
                c = *ch;
                // info!(ctx, "BYTE: {}", *ch);
                // let ch = read_at::<u8>(ctx, i as usize)?;
                i += 1;
            }
            c += 1;

            info!(ctx, "BYTE: {}", c);

            // for i in range.start..range.end {
            //     // //     //info!(ctx, "shit {}", packed_offset);
            //     let ch = read_at::<u8>(ctx, i as usize)?;
            //     // let a = bpf_probe_read_kernel(ch).unwrap();
            //     // //     //info!(ctx, "shit2");
            //     // info!(ctx, "BYTE: {}", *ch);
            //     //     info!(ctx, "shit3 {}", i);
            // }

        }
        _ => {},
    };

    return Ok(xdp_action::XDP_PASS)
}

fn try_filter(ctx: XdpContext) -> Result<u32, u32> {
    info!(&ctx, "received a packet");
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

