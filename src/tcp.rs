use crate::packet::TCPPacket;
use crate::socket::{
    SockID,
    Socket,
    TcpStatus, self
};
use crate::tcpflags;
use anyhow::{Context,Result};
use pnet::packet::ipv4;
use pnet::packet::{
    ip::IpNextHeaderProtocols,
    tcp::TcpPacket,
    Packet
};
use pnet::transport::{
    self,
    TransportChannelType, TransportProtocol
};
use rand::{
    rngs::ThreadRng,
    Rng
};
use std::collections::HashMap;
use std::hash::Hash;
use std::net::{IpAddr,Ipv4Addr};
use std::process::Command;
use std::sync::{
    Arc,
    Condvar,
    Mutex,
    RwLock,
    RwLockWriteGuard,
};
use std::time::{
    Duration,
    SystemTime
};
use std::{
    cmp,
    ops::Range,
    str,
    thread
};

const UNDETERMINED_IP_ADDR : std::net::Ipv4Addr = Ipv4Addr::new(0,0,0,0);
const UNDETERMINED_PORT : u16 = 0;
const MAX_TRANSMITTION : u8 = 5;
const RETRANSMITTION_TIMEOUT : u64 = 3;
const MSS : usize = 1460;
const PORT_RANGE : Range<u16> = 40000..60000;

pub struct TCP {
    //sockets : HashMap<SockID,Socket>,
    sockets : RwLock<HashMap<SockID,Socket>>,
    event_condvar: (Mutex<Option<TCPEvent>>,Condvar),
}

impl TCP {
    pub fn new() -> Arc<Self> {
        //let sockets = HashMap::new();
        //let tcp = Self {sockets};
        let sockets = RwLock::new(HashMap::new());
        let tcp = Arc::new( // Arc で包まれたデータはスレッド間で共同所有できる
            Self {
                sockets, // RwLockで包んだデータをArcで包むことでスレッド間で可変なデータを共有できる
                event_condvar : (Mutex::new(None), Condvar::new()),
            }
        );
        let cloned_tcp = tcp.clone();
        std::thread::spawn(move || {
            cloned_tcp.receive_handler().unwrap();
        });
        tcp
    }


    /// ターゲットに接続して接続済みのソケットのIDを返す
    pub fn connect(&self,addr:Ipv4Addr,port:u16) -> Result<SockID> {
        let mut rng = rand::thread_rng();
        let mut socket = Socket::new(
            TCP::get_source_addr_to(addr)?,
            addr,
            self.select_unused_port(&mut rng)?,
            port,
            TcpStatus::SynSent,
        )?;
        // 初期シーケンス番号はランダムに選ぶ。 以前のシーケンス番号との混乱を避けるため
        socket.send_param.initial_seq = rng.gen_range(1..1 << 31);
        // tcp connectionの確立に成功したらパラメータを設定。
        socket.send_tcp_packet(socket.send_param.initial_seq, 0, tcpflags::SYN, &[])?;
        socket.send_param.unacked_seq = socket.send_param.initial_seq;
        socket.send_param.next = socket.send_param.initial_seq + 1;
        let mut table = self.sockets.write().unwrap();
        let sock_id = socket.get_sock_id();
        table.insert(sock_id,socket);
        // lockを解放
        drop(table);
        self.wait_event(sock_id,TCPEventKind::ConnectionCompleted);
        Ok(sock_id)
    }

    fn select_unused_port(&self,rng:&mut ThreadRng) -> Result<u16> {
        for _ in 0..(PORT_RANGE.end - PORT_RANGE.start) {
            let local_port = rng.gen_range(PORT_RANGE);
            let table = self.sockets.read().unwrap();
            if table.keys().all(|k| local_port != k.2) {
                return Ok(local_port);
            }
        }
        anyhow::bail!("no available port found.");
    }

    /// 宛先IPアドレスに対する送信先インターフェースIPアドレスを取得すru
    fn get_source_addr_to(addr : Ipv4Addr) -> Result<Ipv4Addr> {
        //Ok("172.24.152.150".parse().unwrap())
        let output = Command::new("sh")
            .arg("-c")
            .arg(format!("ip route get {} | grep src", addr))
            .output()?;
        let mut output = str::from_utf8(&output.stdout)?.trim().split_ascii_whitespace();
        while let Some(s) = output.next() {
            if s == "src" {
                break;
            }
        }
        let ip = output.next().context("failed to get src ip")?;
        dbg!("source addr",ip);
        ip.parse().context("failed to parse source ip")
    }

    /// 受信スレッド用のメソッド
    fn receive_handler(&self) -> Result<()> {
        dbg!("begin recv thread");
        let (_,mut receiver) = transport::transport_channel(65535, TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp)).unwrap();
        let mut packet_iter = transport::ipv4_packet_iter(&mut receiver);
        loop {
            let (packet,remote_addr) = match packet_iter.next() {
                Ok((p,r)) => (p,r),
                Err(_) => continue,
            };
            let local_addr = packet.get_destination();
            let tcp_packet = match TcpPacket::new(packet.payload()) {
                Some(p) => p,
                None => {
                    continue;
                }
            };
            let packet = TCPPacket::from(tcp_packet);
            let remote_addr = match remote_addr {
                IpAddr::V4(addr) => addr,
                _ => {
                    continue;
                }
            };
            // loop が回る度にスコープを抜けてlockは解除される
            let mut table = self.sockets.write().unwrap();
            let socket = match table.get_mut(&SockID(
                local_addr,
                remote_addr,
                packet.get_dest(),
                packet.get_src(),
            )) {
                Some(socket) => socket, // 接続済みソケット
                None => match table.get_mut(&SockID(local_addr, UNDETERMINED_IP_ADDR, packet.get_dest(), UNDETERMINED_PORT)) {
                    Some(socket) => socket, // リスニングソケット
                    None => continue,
                }
            };
            if ! packet.is_correct_checksum(local_addr, remote_addr) {
                dbg!("invalid checksum");
                continue;
            }
            let sock_id = socket.get_sock_id();
            if let Err(error) = match socket.status {
                TcpStatus::SynSent => self.synsent_handler(socket, &packet),
                _ => {
                    dbg!("not implemented state");
                    Ok(())
                }
            }
            {
                dbg!(error);
            }
        }
    }
}