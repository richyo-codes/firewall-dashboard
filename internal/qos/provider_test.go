package qos

import "testing"

func TestParsePFQueues(t *testing.T) {
	input := `queue root_em0 on em0 bandwidth 100Mb priority 0 cbq( wrr root )
  [ pkts:       1200  bytes:     900000  dropped pkts:      3 bytes:      2100 ]
  [ qlength:   2/ 50 ]
queue voice parent root_em0 bandwidth 10Mb priority 7 cbq( borrow )
  [ pkts:        400  bytes:     300000  dropped pkts:      0 bytes:         0 ]
  [ qlength:   1/ 25 ]`

	queues := parsePFQueues(input)
	if len(queues) != 2 {
		t.Fatalf("queue count = %d, want 2: %#v", len(queues), queues)
	}
	root := queues[0]
	if root.Name != "root_em0" || root.Interface != "em0" || root.Bandwidth != "100Mb" || root.Scheduler != "cbq" {
		t.Fatalf("root queue metadata = %#v", root)
	}
	if root.Packets != 1200 || root.Bytes != 900000 || root.DroppedPackets != 3 || root.DroppedBytes != 2100 || root.QueueLength != 2 || root.QueueLimit != 50 {
		t.Fatalf("root queue counters = %#v", root)
	}
	if queues[1].Parent != "root_em0" {
		t.Fatalf("child parent = %q", queues[1].Parent)
	}
}

func TestParsePFQueuesEmpty(t *testing.T) {
	if queues := parsePFQueues(""); len(queues) != 0 {
		t.Fatalf("empty output parsed as %#v", queues)
	}
}
