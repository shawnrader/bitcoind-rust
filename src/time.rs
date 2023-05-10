use std::time::{SystemTime, UNIX_EPOCH};

pub fn GetTimeMillis() -> i64
{
    let now = SystemTime::now();
    let duration_since_epoch = now.duration_since(UNIX_EPOCH).unwrap();
    let millis = duration_since_epoch.as_millis();

    millis as i64

}

pub fn GetTimeMicros() -> i64
{
    let now = SystemTime::now();
    let duration_since_epoch = now.duration_since(UNIX_EPOCH).unwrap();
    let micros = duration_since_epoch.as_micros();

    micros as i64
}