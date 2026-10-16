package scheduler

import (
	"context"
	"log"
	"sync"
	"time"
)

// dnsEntryTicker is what the scheduler needs from the DNS entry service
// (service.DNSEntryService satisfies it).
type dnsEntryTicker interface {
	// Tick runs one check of the domain entries and returns how long to wait
	// before the next one.
	Tick(ctx context.Context) time.Duration
	// Wake delivers a request for a check now (a settings change, a restore).
	Wake() <-chan struct{}
}

const (
	// dnsEntryFirstDelay: the first check comes after the boot's own
	// reloads. ReconcileFiles has put the include files in line with
	// the database before any of them, so nothing waits on this check.
	dnsEntryFirstDelay = 10 * time.Second
	// dnsEntryTickTimeout bounds one check: the lookups (5 s each, four names
	// at a time), one transaction, the file writes and one nginx apply. The
	// service ends the lookups at three quarters of it, so a DNS outage leaves
	// the rest for the transaction and the apply.
	dnsEntryTickTimeout = 2 * time.Minute
	// dnsEntryMinWait and dnsEntryMaxWait bound the wait the service asks
	// for, so a mistake can neither spin the loop nor stop it for long.
	dnsEntryMinWait = time.Second
	dnsEntryMaxWait = time.Hour
	// dnsEntryPanicWait is the wait after a check that panicked.
	dnsEntryPanicWait = time.Minute
)

// DNSEntryScheduler runs the domain entry checks (#320): one
// goroutine, one check at a time, each followed by the wait the service
// returns, cut short by a wake. It always runs: NPG_DNS_ENTRIES_DISABLED is
// handled by the service, whose checks keep the files empty while it is set.
type DNSEntryScheduler struct {
	svc        dnsEntryTicker
	firstDelay time.Duration
	ctx        context.Context
	cancel     context.CancelFunc
	stopOnce   sync.Once
	running    bool
	mu         sync.Mutex
}

// NewDNSEntryScheduler constructs (but does not start) the scheduler. Stop
// cancels the context every check runs under.
func NewDNSEntryScheduler(svc dnsEntryTicker) *DNSEntryScheduler {
	ctx, cancel := context.WithCancel(context.Background())
	return &DNSEntryScheduler{svc: svc, firstDelay: dnsEntryFirstDelay, ctx: ctx, cancel: cancel}
}

func (s *DNSEntryScheduler) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running || s.svc == nil {
		return
	}
	s.running = true
	go s.run()
	log.Printf("[Scheduler] DNS entries scheduler started (first check in %v)", s.firstDelay)
}

// Stop ends the loop and cancels a check in progress. It does not wait for
// that check to return.
func (s *DNSEntryScheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return
	}
	s.stopOnce.Do(s.cancel)
	s.running = false
	log.Println("[Scheduler] DNS entries scheduler stopped")
}

func (s *DNSEntryScheduler) run() {
	wait := s.firstDelay
	for {
		t := time.NewTimer(wait)
		select {
		case <-t.C:
		case <-s.svc.Wake():
			t.Stop()
		case <-s.ctx.Done():
			t.Stop()
			return
		}
		if s.ctx.Err() != nil {
			return
		}
		wait = dnsEntryWait(s.tick())
	}
}

// tick runs one check under its own deadline. A panic is logged and the next
// check comes after dnsEntryPanicWait.
func (s *DNSEntryScheduler) tick() (next time.Duration) {
	next = dnsEntryPanicWait
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[Scheduler] ERROR: DNS entries check panicked: %v", r)
		}
	}()
	ctx, cancel := context.WithTimeout(s.ctx, dnsEntryTickTimeout)
	defer cancel()
	return s.svc.Tick(ctx)
}

// dnsEntryWait keeps the wait the service asked for within dnsEntryMinWait
// and dnsEntryMaxWait.
func dnsEntryWait(d time.Duration) time.Duration {
	if d < dnsEntryMinWait {
		return dnsEntryMinWait
	}
	if d > dnsEntryMaxWait {
		return dnsEntryMaxWait
	}
	return d
}
