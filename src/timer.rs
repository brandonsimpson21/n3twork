use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use slab::Slab;
use tokio::sync::mpsc::{self, error::TrySendError};

use crate::error::N3tworkError;
use tracing::warn;

pub struct TimerWheel<T> {
    current_tick: usize,
    wheel_len: usize,
    last_tick: Instant,
    tick_duration: Duration,
    wheel_duration: Duration,
    wheel: Slab<VecDeque<T>>,
    expired: VecDeque<T>,
}

impl<T> std::fmt::Debug for TimerWheel<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TimerWheel")
            .field("current_tick", &self.current_tick)
            .field("wheel_len", &self.wheel_len)
            .field("last_tick", &self.last_tick)
            .field("tick_duration", &self.tick_duration)
            .field("wheel_duration", &self.wheel_duration)
            .finish()
    }
}

impl<T> Default for TimerWheel<T> {
    fn default() -> Self {
        Self::new(Duration::from_secs(1), Duration::from_secs(60 * 30))
    }
}

impl<T> TimerWheel<T> {
    pub fn new(min: Duration, max: Duration) -> Self {
        let wheel_len = (max.as_millis() / min.as_millis()) as usize + 2;
        let tick_duration = min;
        let wheel_duration = max;
        let mut wheel = Slab::with_capacity(wheel_len);
        for _ in 0..wheel_len {
            wheel.insert(VecDeque::new());
        }
        Self {
            current_tick: 0,
            last_tick: Instant::now(),
            tick_duration,
            wheel_duration,
            wheel_len,
            wheel,
            expired: VecDeque::new(),
        }
    }

    pub fn find(&self, timeout: Duration) -> usize {
        let mut timeout = timeout;
        if timeout < self.tick_duration {
            timeout = self.tick_duration;
        } else if timeout > self.wheel_duration {
            timeout = self.wheel_duration;
        }
        let one = Duration::from_millis(1).as_millis();
        let mut tick = (((timeout.as_millis().saturating_sub(one))
            / self.tick_duration.as_millis())
            + one) as usize;
        tick += self.current_tick + 1;
        if tick >= self.wheel_len {
            tick -= self.wheel_len;
        }
        return tick;
    }

    pub fn advance(&mut self, now: Instant) {
        let mut tick =
            now.duration_since(self.last_tick).as_millis() / self.tick_duration.as_millis();

        let adv = tick;
        if tick > self.wheel_len as u128 {
            tick = self.wheel_len as u128;
        }
        for _i in 0..tick {
            self.current_tick += 1;
            if self.current_tick >= self.wheel_len {
                self.current_tick = 0;
            }

            if !self.wheel[self.current_tick].is_empty() {
                while self.wheel[self.current_tick].len() > 0 {
                    let val = self.wheel[self.current_tick].pop_back().unwrap();
                    self.expired.push_back(val);
                }
            }
        }
        self.last_tick =
            self.last_tick + Duration::from_millis((adv * self.tick_duration.as_millis()) as u64);
    }

    pub fn add(&mut self, val: T, timeout: Duration) -> &T {
        let i = self.find(timeout);
        self.wheel[i].push_front(val);
        self.wheel[i].front().expect("unreachable")
    }

    #[inline]
    pub fn purge(&mut self) -> Option<T> {
        self.expired.pop_front()
    }
}

pub struct Ticker {
    period: Duration,
    report_channel: mpsc::Sender<Instant>,
}

impl Ticker {
    pub fn new(period: Duration, report_channel: mpsc::Sender<Instant>) -> Self {
        Self {
            period,
            report_channel: report_channel,
        }
    }

    pub async fn run(&mut self) -> Result<(), N3tworkError> {
        let mut interval = tokio::time::interval(self.period);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let now = Instant::now();
                    if let Err(e) = self.report_channel.try_send(now) {
                        match e {
                            TrySendError::Closed{..} => {
                                warn!("ticker channel closed");
                                break;
                            }
                            TrySendError::Full(_) => {
                                warn!("ticker channel full");
                            }
                        }
                    }
                }
                _ = self.report_channel.closed() => {
                    warn!("ticker channel closed");
                    break;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test_timer {
    use super::*;

    #[tokio::test]
    async fn test_wheel_construction() {
        let wheel: TimerWheel<usize> =
            TimerWheel::new(Duration::from_secs(1), Duration::from_secs(10));
        assert_eq!(wheel.wheel_len, 12);
        assert_eq!(wheel.tick_duration.as_secs(), 1);
        assert_eq!(wheel.wheel_duration.as_secs(), 10);
        assert_eq!(wheel.current_tick, 0);
        assert_eq!(wheel.last_tick.elapsed().as_secs(), 0);

        let mut wheel: TimerWheel<usize> =
            TimerWheel::new(Duration::from_secs(3), Duration::from_secs(10));
        assert_eq!(wheel.wheel_len, 5);
        let i = wheel.purge();
        assert!(i.is_none());
    }

    #[tokio::test]
    async fn test_wheel_find() {
        let mut wheel: TimerWheel<usize> =
            TimerWheel::new(Duration::from_secs(1), Duration::from_secs(10));
        let val = wheel.find(Duration::from_secs(1));
        assert_eq!(val, 2);
        let val = wheel.find(Duration::from_millis(1));
        assert_eq!(val, 2);

        let val = wheel.find(Duration::from_secs(10));
        assert_eq!(val, 11);

        let val = wheel.find(Duration::from_secs(11));
        assert_eq!(val, 11);
        wheel.current_tick = 1;
        let val = wheel.find(Duration::from_secs(1));
        assert_eq!(val, 3);
        let val = wheel.find(Duration::from_secs(10));
        assert_eq!(val, 0);
    }

    #[tokio::test]
    async fn test_wheel_add() {
        let mut wheel: TimerWheel<usize> =
            TimerWheel::new(Duration::from_secs(1), Duration::from_secs(10));
        let _val = wheel.add(1, Duration::from_secs(1));
        assert_eq!(Some(1), wheel.wheel[2].front().copied());
        let _val = wheel.add(2, Duration::from_secs(1));
        assert_eq!(Some(2), wheel.wheel[2].front().copied());
        assert_eq!(Some(1), wheel.wheel[2].back().copied());

        for min in 1..100 {
            let min = Duration::from_secs(min);
            for max in 1..100 {
                let max = Duration::from_secs(max);
                let mut wheel: TimerWheel<usize> = TimerWheel::new(min, max);

                for current in 0..wheel.wheel_len {
                    wheel.current_tick = current;
                    for timeout in 0..wheel.wheel_duration.as_secs() {
                        let tick = wheel.find(Duration::from_secs(timeout));
                        assert!(tick < wheel.wheel_len);
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn test_wheel_purge() {
        let mut wheel: TimerWheel<usize> =
            TimerWheel::new(Duration::from_secs(1), Duration::from_secs(10));
        wheel.advance(Instant::now());
        assert_eq!(0, wheel.current_tick);
        wheel.add(1, Duration::from_secs(1));
        wheel.add(2, Duration::from_secs(1));
        wheel.add(3, Duration::from_secs(2));
        wheel.add(4, Duration::from_secs(2));
        let mut ta = Instant::now().checked_add(Duration::from_secs(3)).unwrap();
        let last_tick = wheel.last_tick;
        wheel.advance(ta);
        assert_eq!(3, wheel.current_tick);
        assert!(wheel.last_tick > last_tick);

        for i in 0..4 {
            let val = wheel.purge();
            assert_eq!(Some(i + 1), val);
        }

        let val = wheel.purge();
        assert!(val.is_none());
        ta = ta.checked_add(Duration::from_secs(5)).unwrap();
        wheel.advance(ta);
        assert_eq!(8, wheel.current_tick);
        ta = ta.checked_add(Duration::from_secs(2)).unwrap();
        wheel.advance(ta);
        assert_eq!(10, wheel.current_tick);

        ta = ta.checked_add(Duration::from_secs(1)).unwrap();
        wheel.advance(ta);
        assert_eq!(11, wheel.current_tick);

        ta = ta.checked_add(Duration::from_secs(1)).unwrap();
        wheel.advance(ta);
        assert_eq!(0, wheel.current_tick);
    }

    #[tokio::test]
    async fn test_ticker() {
        let (tx, mut rx) = mpsc::channel(4);
        let mut ticker = Ticker::new(Duration::from_secs(1), tx);
        let handle = tokio::task::spawn(async move { ticker.run().await });
        let mut now = Instant::now();
        for _ in 0..4 {
            let val = rx.recv().await;
            assert!(val.is_some());
            let val = val.unwrap();
            assert!(val >= now);
            now = val;
        }
        drop(rx);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(handle.is_finished())
    }
}
