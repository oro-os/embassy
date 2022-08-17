#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]

use defmt::info;
use embassy_executor::executor::Spawner;
use embassy_executor::time::{Duration, Timer};
use {defmt_rtt as _, panic_probe as _};

#[embassy_executor::main]
async fn main(_spawner: Spawner) -> ! {
    let _p = embassy_stm32::init(Default::default());
    loop {
        Timer::after(Duration::from_secs(1)).await;
        info!("Hello");
    }
}
