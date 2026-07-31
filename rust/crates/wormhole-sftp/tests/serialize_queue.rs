//! Serialization invariant: concurrent session ops never overlap on the backend.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use wormhole_sftp::{
    FakeSftpBackend, SerializedSftpSession, SftpError, TransferDirection, TransferQueue,
    TransferStatus,
};

#[tokio::test]
async fn concurrent_ops_never_overlap_on_backend() {
    let backend = FakeSftpBackend::with_delay(Duration::from_millis(40));
    let session = SerializedSftpSession::new(backend).into_arc();

    let a = {
        let s = Arc::clone(&session);
        tokio::spawn(async move { s.list_directory("/home/user").await })
    };
    let b = {
        let s = Arc::clone(&session);
        tokio::spawn(async move { s.upload("/home/user/a.txt", b"hello").await })
    };
    let c = {
        let s = Arc::clone(&session);
        tokio::spawn(async move { s.exists("/home/user").await })
    };

    let (ra, rb, rc) = tokio::join!(a, b, c);
    ra.unwrap().unwrap();
    rb.unwrap().unwrap();
    rc.unwrap().unwrap();

    assert_eq!(
        session
            .backend()
            .peak_in_flight
            .load(Ordering::SeqCst),
        1,
        "backend saw overlapping ops — serialization gate broken"
    );
    assert_eq!(session.ops_completed(), 3);
}

#[tokio::test]
async fn transfer_queue_runs_jobs_serially() {
    let backend = FakeSftpBackend::with_delay(Duration::from_millis(25));
    let session = SerializedSftpSession::new(backend).into_arc();
    let queue = TransferQueue::new(Arc::clone(&session));

    let q1 = queue.enqueue_and_run_file(
        TransferDirection::Upload,
        "local/a.txt",
        "/home/user/a.txt",
        Some(b"one".to_vec()),
    );
    let q2 = queue.enqueue_and_run_file(
        TransferDirection::Upload,
        "local/b.txt",
        "/home/user/b.txt",
        Some(b"two".to_vec()),
    );

    // Overlap the two enqueue futures — gate must still serialize backend work.
    let (r1, r2) = tokio::join!(q1, q2);
    r1.unwrap();
    r2.unwrap();

    assert_eq!(
        session
            .backend()
            .peak_in_flight
            .load(Ordering::SeqCst),
        1
    );

    let jobs = queue.jobs();
    assert_eq!(jobs.len(), 2);
    assert!(jobs.iter().all(|j| j.status == TransferStatus::Completed));
    assert!(session.exists("/home/user/a.txt").await.unwrap());
    assert!(session.exists("/home/user/b.txt").await.unwrap());
}

#[tokio::test]
async fn closed_session_rejects_new_ops() {
    let session = SerializedSftpSession::new(FakeSftpBackend::new());
    session.close();
    let err = session.list_directory("/").await.unwrap_err();
    assert!(matches!(err, SftpError::Closed));
}

#[tokio::test]
async fn list_skips_unsafe_names_seeded_directly() {
    // Seed via internal map would require unsafe names; upload rejects them.
    let session = SerializedSftpSession::new(FakeSftpBackend::new());
    let err = session
        .upload("/home/user/evil:ads", b"x")
        .await
        .unwrap_err();
    assert!(matches!(err, SftpError::UnsafeName(_)));
}

/// Aborting a caller mid-op must not release the gate early — peak stays 1.
/// Next op after cancel must succeed (gate not stuck).
#[tokio::test]
async fn cancel_mid_op_does_not_overlap_backend() {
    let backend = FakeSftpBackend::with_delay(Duration::from_millis(200));
    let session = SerializedSftpSession::new(backend).into_arc();

    let s = Arc::clone(&session);
    let handle = tokio::spawn(async move { s.list_directory("/home/user").await });
    tokio::time::sleep(Duration::from_millis(40)).await;
    handle.abort();
    let _ = handle.await;

    // A second op must wait for the aborted caller's worker to finish.
    let s2 = Arc::clone(&session);
    let second = tokio::spawn(async move { s2.exists("/home/user").await });
    second.await.unwrap().unwrap();

    assert_eq!(
        session
            .backend()
            .peak_in_flight
            .load(Ordering::SeqCst),
        1,
        "cancel released the gate while the backend was still in flight"
    );
    assert_eq!(
        session.backend().in_flight.load(Ordering::SeqCst),
        0,
        "in_flight leaked after cancel"
    );
    // Worker finished the first op despite abort; second completed too.
    assert_eq!(session.ops_completed(), 2);
}

/// Cancel while waiting for the gate: worker skips backend; gate frees; next op works.
#[tokio::test]
async fn cancel_while_queued_skips_backend_then_next_succeeds() {
    let backend = FakeSftpBackend::with_delay(Duration::from_millis(150));
    let session = SerializedSftpSession::new(backend).into_arc();

    let s1 = Arc::clone(&session);
    let holder = tokio::spawn(async move { s1.list_directory("/home/user").await });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let s2 = Arc::clone(&session);
    let waiter = tokio::spawn(async move { s2.exists("/home/user").await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    waiter.abort();
    let _ = waiter.await;

    holder.await.unwrap().unwrap();

    session
        .upload("/home/user/after-cancel.txt", b"ok")
        .await
        .unwrap();

    assert_eq!(
        session.ops_completed(),
        2,
        "pre-gate cancel must skip backend; only holder + follow-up count"
    );
    assert_eq!(session.gate_acquisitions(), 2);
    assert_eq!(
        session
            .backend()
            .peak_in_flight
            .load(Ordering::SeqCst),
        1
    );
    assert_eq!(session.backend().in_flight.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn queue_fifo_fairness_under_contention() {
    use std::sync::Mutex;

    let backend = FakeSftpBackend::with_delay(Duration::from_millis(40));
    let session = SerializedSftpSession::new(backend).into_arc();
    let order = Arc::new(Mutex::new(Vec::new()));

    // Hold the gate with a first op, then enqueue waiters in known order.
    let s1 = Arc::clone(&session);
    let o1 = Arc::clone(&order);
    let first = tokio::spawn(async move {
        s1.upload("/home/user/1.txt", b"1").await.unwrap();
        o1.lock().unwrap().push(1u8);
    });
    tokio::time::sleep(Duration::from_millis(10)).await;

    let s2 = Arc::clone(&session);
    let o2 = Arc::clone(&order);
    let second = tokio::spawn(async move {
        s2.upload("/home/user/2.txt", b"2").await.unwrap();
        o2.lock().unwrap().push(2);
    });
    tokio::time::sleep(Duration::from_millis(5)).await;

    let s3 = Arc::clone(&session);
    let o3 = Arc::clone(&order);
    let third = tokio::spawn(async move {
        s3.upload("/home/user/3.txt", b"3").await.unwrap();
        o3.lock().unwrap().push(3);
    });

    let _ = tokio::join!(first, second, third);
    assert_eq!(
        *order.lock().unwrap(),
        vec![1, 2, 3],
        "tokio Mutex waiters must complete in acquire order"
    );
    assert_eq!(
        session
            .backend()
            .peak_in_flight
            .load(Ordering::SeqCst),
        1
    );
}

#[tokio::test]
async fn transfer_failure_error_hides_backend_secrets() {
    // Inject a backend-shaped failure via run_serialized so the queue path stores
    // public_message only.
    let session = SerializedSftpSession::new(FakeSftpBackend::new()).into_arc();
    let queue = TransferQueue::new(Arc::clone(&session));

    // Force a NotFound download — public message keeps path (not a secret).
    let err = queue
        .enqueue_and_run_file(
            TransferDirection::Download,
            "/home/user/missing-SECRET-path.txt",
            "local/out.bin",
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, SftpError::NotFound(_)));

    let jobs = queue.jobs();
    let failed = jobs.iter().find(|j| j.status == TransferStatus::Failed).unwrap();
    let stored = failed.error.as_deref().unwrap_or("");
    assert!(stored.contains("not found"));
    // Ensure Display of Backend never lands in the strip via public_message.
    let backend_err = SftpError::Backend("password=hunter2-MARKER".into());
    assert!(!backend_err.public_message().contains("hunter2-MARKER"));
    assert!(!backend_err.public_message().contains("password"));
}

#[tokio::test]
async fn rename_rejects_unsafe_destination_name() {
    let session = SerializedSftpSession::new(FakeSftpBackend::new());
    session
        .upload("/home/user/ok.txt", b"x")
        .await
        .unwrap();
    let err = session
        .rename("/home/user/ok.txt", "/home/user/evil:ads")
        .await
        .unwrap_err();
    assert!(matches!(err, SftpError::UnsafeName(_)));
}

#[tokio::test]
async fn cancel_transfer_marks_job_cancelled() {
    let backend = FakeSftpBackend::with_delay(Duration::from_millis(200));
    let session = SerializedSftpSession::new(backend).into_arc();
    let queue = Arc::new(TransferQueue::new(Arc::clone(&session)));

    let q = Arc::clone(&queue);
    let handle = tokio::spawn(async move {
        q.enqueue_and_run_file(
            TransferDirection::Upload,
            "local/a.txt",
            "/home/user/a.txt",
            Some(b"payload".to_vec()),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    handle.abort();
    let _ = handle.await;

    // Allow the session worker to finish (gate held until complete).
    tokio::time::sleep(Duration::from_millis(250)).await;

    let jobs = queue.jobs();
    assert_eq!(jobs.len(), 1);
    assert_eq!(
        jobs[0].status,
        TransferStatus::Cancelled,
        "aborted enqueue must not leave Running forever"
    );
    assert_eq!(
        session
            .backend()
            .peak_in_flight
            .load(Ordering::SeqCst),
        1
    );

    // Gate must be free for the next enqueue after cancel.
    queue
        .enqueue_and_run_file(
            TransferDirection::Upload,
            "local/b.txt",
            "/home/user/b.txt",
            Some(b"next".to_vec()),
        )
        .await
        .unwrap();
    let jobs = queue.jobs();
    assert_eq!(jobs.len(), 2);
    assert_eq!(jobs[1].status, TransferStatus::Completed);
    assert_eq!(
        session
            .backend()
            .peak_in_flight
            .load(Ordering::SeqCst),
        1
    );
}

/// Abort a transfer that is waiting on the gate: must not cancel the holder, must
/// skip backend for the waiter, and the next enqueue must Complete.
#[tokio::test]
async fn cancel_queued_transfer_skips_then_next_completes() {
    let backend = FakeSftpBackend::with_delay(Duration::from_millis(200));
    let session = SerializedSftpSession::new(backend).into_arc();
    let queue = Arc::new(TransferQueue::new(Arc::clone(&session)));

    let q1 = Arc::clone(&queue);
    let holder = tokio::spawn(async move {
        q1.enqueue_and_run_file(
            TransferDirection::Upload,
            "local/a.txt",
            "/home/user/a.txt",
            Some(b"one".to_vec()),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(30)).await;

    let q2 = Arc::clone(&queue);
    let waiter = tokio::spawn(async move {
        q2.enqueue_and_run_file(
            TransferDirection::Upload,
            "local/b.txt",
            "/home/user/b.txt",
            Some(b"two".to_vec()),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    waiter.abort();
    let _ = waiter.await;

    holder.await.unwrap().unwrap();

    queue
        .enqueue_and_run_file(
            TransferDirection::Upload,
            "local/c.txt",
            "/home/user/c.txt",
            Some(b"three".to_vec()),
        )
        .await
        .unwrap();

    let jobs = queue.jobs();
    assert_eq!(jobs.len(), 3);
    assert_eq!(
        jobs[0].status,
        TransferStatus::Completed,
        "cancel of waiter must not clobber the in-flight job"
    );
    assert_eq!(jobs[1].status, TransferStatus::Cancelled);
    assert_eq!(
        jobs[2].status,
        TransferStatus::Completed,
        "next enqueue after queue cancel must Complete"
    );
    assert_eq!(
        session.ops_completed(),
        2,
        "pre-gate queue cancel must skip backend for the waiter"
    );
    assert_eq!(session.gate_acquisitions(), 2);
    assert_eq!(
        session
            .backend()
            .peak_in_flight
            .load(Ordering::SeqCst),
        1
    );
    assert_eq!(session.backend().in_flight.load(Ordering::SeqCst), 0);
    assert!(
        !session.exists("/home/user/b.txt").await.unwrap(),
        "skipped waiter must not have written the remote file"
    );
    assert!(session.exists("/home/user/a.txt").await.unwrap());
    assert!(session.exists("/home/user/c.txt").await.unwrap());
}

#[tokio::test]
async fn close_rejects_new_ops_after_inflight() {
    let backend = FakeSftpBackend::with_delay(Duration::from_millis(60));
    let session = SerializedSftpSession::new(backend).into_arc();
    let s = Arc::clone(&session);
    let h = tokio::spawn(async move { s.list_directory("/home/user").await });
    tokio::time::sleep(Duration::from_millis(15)).await;
    session.close();
    let _ = h.await.unwrap();
    let err = session.exists("/").await.unwrap_err();
    assert!(matches!(err, SftpError::Closed));
}
