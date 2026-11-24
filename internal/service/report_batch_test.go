package service

import (
	"errors"
	"maps"
	"testing"

	"github.com/cedar2025/xboard-node/internal/controlplane"
	"github.com/cedar2025/xboard-node/internal/tracker"
	"github.com/google/uuid"
)

type batchTestPanel struct {
	controlplane.ControlPlane
	reports []controlplane.ReportPayload
	support bool
}

func (*batchTestPanel) Metrics() controlplane.APIMetrics { return controlplane.APIMetrics{} }

func (p *batchTestPanel) SupportsTrafficBatchDedup() bool { return p.support }

func (p *batchTestPanel) Report(payload controlplane.ReportPayload) error {
	p.reports = append(p.reports, payload)
	if len(p.reports) == 1 {
		return errors.New("reply lost")
	}
	return nil
}

func TestTrafficBatchRetryDoesNotMergeNewTraffic(t *testing.T) {
	p := &batchTestPanel{support: true}
	s := newTestService(&fakeKernel{running: true})
	s.source, s.sink, s.tracker = p, p, tracker.New()
	s.tracker.Process(map[int][2]int64{1: {10, 12}}, nil, 0)
	if err := s.sendReport(); err == nil {
		t.Fatal("first send should fail")
	}
	s.tracker.Process(map[int][2]int64{1: {15, 20}, 2: {2, 3}}, nil, 0)
	for range 3 {
		if err := s.sendReport(); err != nil {
			t.Fatal(err)
		}
	}
	first, retry, next, idle := p.reports[0], p.reports[1], p.reports[2], p.reports[3]
	if _, err := uuid.Parse(first.TrafficBatchID); err != nil {
		t.Fatalf("invalid batch ID: %v", err)
	}
	if first.TrafficBatchID != retry.TrafficBatchID || !maps.Equal(first.Traffic, retry.Traffic) {
		t.Fatal("retry changed the batch")
	}
	want := map[int][2]int64{1: {5, 8}, 2: {2, 3}}
	if next.TrafficBatchID == "" || next.TrafficBatchID == retry.TrafficBatchID || !maps.Equal(next.Traffic, want) {
		t.Fatalf("new traffic was not isolated in a new batch: %v", next.Traffic)
	}
	if idle.TrafficBatchID != "" || len(idle.Traffic) != 0 {
		t.Fatal("created a batch for empty traffic")
	}
}

func TestTrafficReportRetainsLegacyRetryWithoutDedupCapability(t *testing.T) {
	p := &batchTestPanel{}
	s := newTestService(&fakeKernel{running: true})
	s.source, s.sink, s.tracker = p, p, tracker.New()
	s.tracker.Process(map[int][2]int64{1: {10, 12}}, nil, 0)
	if err := s.sendReport(); err == nil {
		t.Fatal("first send should fail")
	}
	s.tracker.Process(map[int][2]int64{1: {15, 20}}, nil, 0)
	if err := s.sendReport(); err != nil {
		t.Fatal(err)
	}
	retry := p.reports[1]
	if retry.TrafficBatchID != "" || !maps.Equal(retry.Traffic, map[int][2]int64{1: {15, 20}}) {
		t.Fatalf("legacy retry changed: %+v", retry)
	}
}
