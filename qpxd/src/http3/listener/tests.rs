use crate::http3::listener::scheduler::PriorityScheduler;
use crate::http3::listener::*;

#[test]
fn classify_h3_connect_kind_rejects_unknown_extended_connect_protocols() {
    assert_eq!(classify_h3_connect_kind(None), H3ConnectKind::Connect);
    assert_eq!(
        classify_h3_connect_kind(Some(::h3::ext::Protocol::CONNECT_UDP)),
        H3ConnectKind::ConnectUdp
    );
    assert_eq!(
        classify_h3_connect_kind(Some(::h3::ext::Protocol::WEB_TRANSPORT)),
        H3ConnectKind::Extended(::h3::ext::Protocol::WEB_TRANSPORT)
    );
}

#[test]
fn priority_scheduler_prioritizes_urgency_and_non_incremental_work() {
    let mut scheduler = PriorityScheduler::new();
    scheduler.enqueue(
        "low",
        crate::http3::priority::StreamPriority {
            urgency: 7,
            incremental: false,
        },
    );
    scheduler.enqueue(
        "high-incremental",
        crate::http3::priority::StreamPriority {
            urgency: 0,
            incremental: true,
        },
    );
    scheduler.enqueue(
        "high",
        crate::http3::priority::StreamPriority {
            urgency: 0,
            incremental: false,
        },
    );

    assert_eq!(scheduler.next_task(), Some("high"));
    assert_eq!(scheduler.next_task(), Some("high-incremental"));
    assert_eq!(scheduler.next_task(), Some("low"));
    assert_eq!(scheduler.next_task(), None);
}

#[test]
fn priority_scheduler_orders_incremental_work_by_urgency() {
    let mut scheduler = PriorityScheduler::new();
    scheduler.enqueue(
        "u0-a",
        crate::http3::priority::StreamPriority {
            urgency: 0,
            incremental: true,
        },
    );
    scheduler.enqueue(
        "u0-b",
        crate::http3::priority::StreamPriority {
            urgency: 0,
            incremental: true,
        },
    );
    scheduler.enqueue(
        "u7",
        crate::http3::priority::StreamPriority {
            urgency: 7,
            incremental: true,
        },
    );

    assert_eq!(scheduler.next_task(), Some("u0-a"));
    assert_eq!(scheduler.next_task(), Some("u0-b"));
    assert_eq!(scheduler.next_task(), Some("u7"));
    assert_eq!(scheduler.next_task(), None);
}
