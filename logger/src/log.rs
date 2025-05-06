use tracing::Level;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub fn setup() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::filter::LevelFilter::from_level(
            Level::DEBUG,
        ))
        .with(
            tracing_subscriber::fmt::layer()
                .pretty()
                .with_file(false)
                .with_target(false)
                .with_thread_ids(false)
                .with_thread_names(false),
        )
        .init();
}
