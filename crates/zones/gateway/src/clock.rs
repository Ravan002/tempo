use eyre::{Result, eyre};
use std::{
    sync::{Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

/// Time that includes host suspension, used only for local evidence deadlines.
pub fn continuous_seconds() -> f64 {
    #[cfg(target_os = "macos")]
    {
        #[repr(C)]
        struct Timebase {
            numerator: u32,
            denominator: u32,
        }
        unsafe extern "C" {
            fn mach_continuous_time() -> u64;
            fn mach_timebase_info(info: *mut Timebase) -> i32;
        }
        static SCALE: OnceLock<f64> = OnceLock::new();
        let scale = SCALE.get_or_init(|| {
            let mut base = Timebase {
                numerator: 0,
                denominator: 0,
            };
            // SAFETY: the OS writes exactly one initialized Timebase structure.
            let result = unsafe { mach_timebase_info(&mut base) };
            assert_eq!(result, 0);
            f64::from(base.numerator) / f64::from(base.denominator) / 1e9
        });
        // SAFETY: this OS clock takes no pointers and has no mutable process state.
        (unsafe { mach_continuous_time() } as f64) * scale
    }
    #[cfg(target_os = "linux")]
    {
        let mut time = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: clock_gettime writes into a valid timespec; BOOTTIME includes suspend.
        let result = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) };
        assert_eq!(result, 0);
        time.tv_sec as f64 + time.tv_nsec as f64 / 1e9
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    compile_error!("zones-gateway requires a suspend-aware OS clock");
}

pub fn unix_seconds() -> Result<u64> {
    static LAST: OnceLock<Mutex<Option<(f64, f64)>>> = OnceLock::new();
    let utc = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64();
    let boot = continuous_seconds();
    let mut last = LAST
        .get_or_init(|| Mutex::new(None))
        .lock()
        .map_err(|_| eyre!("clock health unavailable"))?;
    if let Some((previous_utc, previous_boot)) = *last {
        let expected = previous_utc + boot - previous_boot;
        if (utc - expected).abs() > 1.0 {
            // Hold the previous reference so a jump cannot reset its own health check.
            return Err(eyre!("UTC clock moved relative to continuous time"));
        }
    }
    *last = Some((utc, boot));
    Ok(utc as u64)
}
