#!/usr/bin/env python3
"""The cross-repository target lease refuses a stale holder (KDEC-030 draft, lane L-SEAM).

WHY THIS EXISTS (docs/architecture/LZ_KIT_SEAM_CONTRACT.md, "The lease")

    The kit serialises its own deploys and rollbacks on a GitHub Actions concurrency group. A
    concurrency group is evaluated inside ONE repository, so a landing-zone apply in the platform
    repository and a kit deploy in an application repository never wait for each other, whatever
    the group is called. KDEC-030 proposes one lease per target that BOTH pipelines acquire before
    they mutate it -- an Azure Storage blob lease plus a generation number (the fencing token),
    checked again before every mutation. A lock that a holder can lose without noticing is not a
    lock; these cases prove the model refuses the holder that lost it.

    This is the stub-level proof the lane can give without touching a workflow: the lease model is
    pure Python over an in-memory emulation of the Lease Blob REST semantics (lease states and
    status codes as Microsoft Learn documents them). The CLI, the live REST adapter and the opt-in
    deploy wiring are proven across two callers by tests/prove_target_lease_crossrepo.py; the live
    blob, the identities and the LZ pipelines are owed (the contract's "Negative tests to build").

THE CASES
    B1-B5  the blob-lease emulation itself follows the documented semantics (duration bounds, 409
           on a held lease, 412 on a write without the lease, break needs no lease id, a broken
           lease cannot be renewed)
    L1     the LZ apply holds the target; the kit's deploy is refused LEASE_HELD, naming the holder
    L2     FENCING: the kit's lease is broken and the LZ takes the target; the kit's next mutation
           is refused STALE_LEASE_HOLDER (its lease id is no longer valid) -- the case this exists for
    L3     FENCING: broken, and nobody has re-acquired yet; the old holder is still refused
    L4     FENCING: a holder past its own logical expiry is refused even though the blob is still
           leased to it (it stopped heart-beating; a contender may take over at any moment)
    L5     FENCING: a token whose generation is not the blob's current generation is refused even
           with the live lease id (a token copied from an earlier acquisition); and (L5b) one with
           the current generation and holder name but not the live lease id
    L6     the generation is strictly increasing across acquisitions, takeovers and breaks
    L7     an expired holder that left the target CLEAN is taken over automatically, generation + 1,
           and the old holder is then fenced
    L8     an expired holder that left the target MID-MUTATION is NOT taken over:
           LEASE_ABANDONED_MID_MUTATION, a human decision
    L9     breaking a lease is refused for an actor outside the break authority, and recorded for
           one inside it
    L10    a lease lost DURING a mutation is detected after it: MUTATED_WITHOUT_LEASE, ending
           ROLLBACK_REQUIRES_HUMAN_DECISION, never reported as a clean mutation
    L11    a holder cannot release while it is mid-mutation (the state would read clean)
    L12    CONTROL: the rightful holder passes every fence, mutates, heart-beats and releases, and the
           next acquirer gets the target

EXIT  0 all hold   1 any does not   2 could not be checked (UNKNOWN, never PASS)
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), 'scripts'))

FAILS = []


def expect(cond, label):
    print('%s  %s' % ('ok  ' if cond else 'FAIL', label))
    if not cond:
        FAILS.append(label)


def raises(fn, code):
    """-> True when fn raises a lease error whose code is `code`."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        return getattr(e, 'code', None) == code
    return False


def main():
    try:
        import target_lease as T
    except Exception as e:  # noqa: BLE001
        print('UNKNOWN: scripts/target_lease.py could not be imported (%s)' % e)
        return 2

    TGT = 'prod/rg-app/app-a'
    LZ, KIT = 'lz-apply:run-11', 'kit-deploy:run-22'
    AUTH = {'platform-admins'}

    # --------------------------------------------------------------- B: the emulation
    s = T.BlobLeaseStore()
    expect(raises(lambda: s.acquire('b', 10, 'x', 0), 400), 'B1 a lease of 10 s is refused (15-60 or -1)')
    lid = s.acquire('b', 30, 'id-a', 0)
    expect(lid == 'id-a' and raises(lambda: s.acquire('b', 30, 'id-b', 1), 409),
           'B2 a held lease refuses another acquirer with 409')
    expect(raises(lambda: s.write('b', None, {'k': 'v'}, 1), 412),
           'B3 a write without the lease id on a leased blob fails 412')
    s.break_lease('b', 0, 2)
    expect(s.state('b', 2) == 'broken', 'B4 break needs no lease id; period 0 breaks at once')
    expect(raises(lambda: s.renew('b', 'id-a', 3), 409), 'B5 a broken lease cannot be renewed')

    # --------------------------------------------------------------- L: the seam lease
    store = T.BlobLeaseStore()
    L = T.TargetLease(store, heartbeat_ttl=600, break_authority=AUTH)

    lz = L.acquire(TGT, LZ, now=0)
    try:
        L.acquire(TGT, KIT, now=5)
        expect(False, 'L1 the kit is refused while the LZ apply holds the target')
    except T.LeaseError as e:
        expect(e.code == 'LEASE_HELD' and LZ in str(e),
               'L1 the kit is refused LEASE_HELD while the LZ apply holds the target, naming it')

    # L2: the LZ's lease is broken by the break authority; the kit takes the target; the LZ's
    # next mutation is fenced.
    L.break_lease(TGT, 'platform-admins', 'apply runner lost', now=10)
    kit = L.acquire(TGT, KIT, now=11)
    expect(raises(lambda: L.fence(lz, now=12), 'STALE_LEASE_HOLDER'),
           'L2 FENCING: the broken LZ holder is refused once the kit holds the target')
    expect(kit.generation == lz.generation + 2,
           'L6a generation rose through the break (+1) and the new acquisition (+1)')

    # L3: broken with nobody re-acquiring.
    store3 = T.BlobLeaseStore()
    L3 = T.TargetLease(store3, heartbeat_ttl=600, break_authority=AUTH)
    a = L3.acquire(TGT, KIT, now=0)
    L3.break_lease(TGT, 'platform-admins', 'test', now=1)
    expect(raises(lambda: L3.fence(a, now=2), 'STALE_LEASE_HOLDER'),
           'L3 FENCING: a broken holder is refused even when nobody has re-acquired')

    # L4: past its own logical expiry.
    store4 = T.BlobLeaseStore()
    L4 = T.TargetLease(store4, heartbeat_ttl=600, break_authority=AUTH)
    b = L4.acquire(TGT, KIT, now=0)
    expect(raises(lambda: L4.fence(b, now=601), 'LEASE_EXPIRED_HOLDER'),
           'L4 FENCING: a holder past its heartbeat expiry is refused though the blob is still leased')

    # L5: a token with the live lease id but an old generation.
    store5 = T.BlobLeaseStore()
    L5 = T.TargetLease(store5, heartbeat_ttl=600, break_authority=AUTH)
    c = L5.acquire(TGT, KIT, now=0)
    forged = T.Token(c.target, c.lease_id, c.generation - 1, c.holder)
    expect(raises(lambda: L5.fence(forged, now=1), 'STALE_LEASE_HOLDER'),
           'L5 FENCING: a token whose generation is not current is refused')
    impostor = T.Token(c.target, 'not-the-lease-id', c.generation, c.holder)
    expect(raises(lambda: L5.fence(impostor, now=1), 'STALE_LEASE_HOLDER'),
           'L5b FENCING: the right generation and holder name without the live lease id is refused')

    # L6b/L7: expired-clean takeover, generation + 1, old holder fenced.
    store7 = T.BlobLeaseStore()
    L7 = T.TargetLease(store7, heartbeat_ttl=600, break_authority=AUTH)
    old = L7.acquire(TGT, KIT, now=0)
    new = L7.acquire(TGT, LZ, now=700)
    expect(new.holder == LZ and new.generation == old.generation + 1 and new.took_over == KIT,
           'L7 an expired CLEAN holder is taken over automatically, generation + 1, recorded')
    expect(raises(lambda: L7.fence(old, now=701), 'STALE_LEASE_HOLDER'),
           'L7 the expired holder is fenced after the takeover')
    g = []
    st6 = T.BlobLeaseStore()
    L6 = T.TargetLease(st6, heartbeat_ttl=600, break_authority=AUTH)
    for i in range(3):
        t = L6.acquire(TGT, 'h%d' % i, now=i * 10)
        g.append(t.generation)
        L6.release(t, now=i * 10 + 1)
    expect(g == sorted(set(g)) and len(g) == 3, 'L6b generations strictly increase: %s' % g)

    # L8: expired mid-mutation is not taken over.
    store8 = T.BlobLeaseStore()
    L8 = T.TargetLease(store8, heartbeat_ttl=600, break_authority=AUTH)
    d = L8.acquire(TGT, KIT, now=0)
    L8.begin_mutation(d, 'containerapp update image', now=1)
    expect(raises(lambda: L8.acquire(TGT, LZ, now=900), 'LEASE_ABANDONED_MID_MUTATION'),
           'L8 an expired holder that left the target mid-mutation is NOT taken over')

    # L9: break authority.
    expect(raises(lambda: L8.break_lease(TGT, 'kit-deploy-identity', 'impatient', now=901),
                  'BREAK_NOT_AUTHORISED'),
           'L9 a break by an actor outside the break authority is refused')
    rec = L8.break_lease(TGT, 'platform-admins', 'abandoned mid-mutation; human reviewed', now=902)
    expect(rec.get('broken_by') == 'platform-admins' and rec.get('reason'),
           'L9 a break by the authority is recorded with who and why')

    # L10: lease lost during the mutation.
    store10 = T.BlobLeaseStore()
    L10 = T.TargetLease(store10, heartbeat_ttl=600, break_authority=AUTH)
    e = L10.acquire(TGT, KIT, now=0)

    def mutation():
        L10.break_lease(TGT, 'platform-admins', 'broken during the mutation', now=5)

    res = L10.mutate(e, 'containerapp update image', mutation, now=4, after=6)
    expect(res['outcome'] == 'MUTATED_WITHOUT_LEASE'
           and res['rollback_state'] == 'ROLLBACK_REQUIRES_HUMAN_DECISION',
           'L10 a lease lost during the mutation is detected: MUTATED_WITHOUT_LEASE, human decision')

    # L11: no release mid-mutation.
    store11 = T.BlobLeaseStore()
    L11 = T.TargetLease(store11, heartbeat_ttl=600, break_authority=AUTH)
    f = L11.acquire(TGT, KIT, now=0)
    L11.begin_mutation(f, 'swap', now=1)
    expect(raises(lambda: L11.release(f, now=2), 'RELEASE_MID_MUTATION'),
           'L11 a holder cannot release while mid-mutation')

    # L12: control.
    store12 = T.BlobLeaseStore()
    L12 = T.TargetLease(store12, heartbeat_ttl=600, break_authority=AUTH)
    h = L12.acquire(TGT, KIT, now=0)
    ok = True
    try:
        L12.fence(h, now=1)
        r = L12.mutate(h, 'containerapp update image', lambda: None, now=2, after=3)
        ok = r['outcome'] == 'MUTATED_UNDER_LEASE'
        L12.heartbeat(h, now=500)
        L12.fence(h, now=1000)          # within the renewed expiry (500 + 600)
        L12.release(h, now=1001)
        nxt = L12.acquire(TGT, LZ, now=1002)
        ok = ok and nxt.generation == h.generation + 1 and nxt.took_over is None
    except Exception as ex:  # noqa: BLE001
        print('     control raised %r' % ex)
        ok = False
    expect(ok, 'L12 CONTROL: the rightful holder fences, mutates, heart-beats, releases; the next acquires')

    print()
    if FAILS:
        print('NOT PROVEN: %d case(s) decided wrongly.' % len(FAILS))
        return 1
    print('PROVEN: the target lease refuses every stale holder; the rightful holder is not refused.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
